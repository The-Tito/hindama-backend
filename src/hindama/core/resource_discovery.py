"""Discovering the resources each identity owns (RF-36, CU-10 step 3; RN-01, RN-11).

Only GET listing operations of the current contract are called: without path parameters and with a
2xx answer declared as an array, or as an object with an array. The resource type is the last
segment of the path (`/orders` → `orders`) and the identifier, the `id` field of each element.

Every request goes through `SafeHttpClient`, bound to the project's verified host (ADR-008), and
none follows redirects. One discovery sends at most `MAX_REQUESTS` requests (logins included) and
lasts at most `TIMEOUT_SECONDS`: whatever was found until then is kept and `truncated` is set.

Nothing here logs or returns the credential: only identifiers, status codes and a failure kind.
"""

import asyncio
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hindama.core.credentials import Credential
from hindama.core.destinations import IPAddress, Resolver
from hindama.core.identity_probe import (
    PROBE_LIMITS,
    LoginRequest,
    credential_headers,
    log_in,
)
from hindama.core.openapi_import import resolve_ref
from hindama.core.safe_http import (
    BlockReason,
    DestinationBlockedError,
    InvalidUrl,
    NetworkError,
    ResponseTooLargeError,
    SafeHttpClient,
)
from hindama.models.enums import AuthType

MAX_REQUESTS = 100  # contract, `discoverResources`
TIMEOUT_SECONDS = 25.0
MAX_TYPE_LENGTH = 100  # `Resource.resource_type`
MAX_VALUE_LENGTH = 500  # `Resource.value`
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class DiscoveryFailure(StrEnum):
    """`DiscoveryIdentityResult.failure`: the first four mean what they mean in `IdentityTest`."""

    REJECTED = "rejected"
    LOGIN_FAILED = "login_failed"
    CONNECTION_ERROR = "connection_error"
    DESTINATION_NOT_ALLOWED = "destination_not_allowed"
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True, slots=True)
class ListOperation:
    url: str
    resource_type: str
    array_field: str | None  # where the array is in an object answer; `None` for a bare array


@dataclass(frozen=True, slots=True)
class Searcher:
    """An identity, with what it needs to authenticate. `login` only with `auth_type` login; a
    login identity without it (its operation left the contract) fails with `login_failed`."""

    identity_id: Any
    auth_type: AuthType
    credential: Credential
    field_name: str | None = None
    login: LoginRequest | None = None


@dataclass(slots=True)
class IdentityFindings:
    identity_id: Any
    found: list[tuple[str, str]] = field(default_factory=list)  # (type, identifier), no repeats
    failure: DiscoveryFailure | None = DiscoveryFailure.NOT_ATTEMPTED

    def add(self, resource_type: str, value: str) -> None:
        if (resource_type, value) not in self.found:
            self.found.append((resource_type, value))


@dataclass(slots=True)
class DiscoveryResult:
    identities: list[IdentityFindings]
    requests_sent: int = 0
    truncated: bool = False


# ------------------------------------------------------------------ the contract


def resource_type(path: str) -> str | None:
    """The last segment of a path without parameters, if it can name a resource."""
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    if not segment or len(segment) > MAX_TYPE_LENGTH or _CONTROL.search(segment):
        return None
    return segment


def _is_array(schema: Any) -> bool:
    if not isinstance(schema, dict):
        return False
    kind = schema.get("type")
    kinds = kind if isinstance(kind, list) else [kind]
    return "array" in kinds


def _is_json(media: str) -> bool:
    media = media.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def array_location(responses: Mapping[str, Any], document: Any) -> tuple[bool, str | None]:
    """Whether a stored `responses` declares a listing, and where its array is: `(True, None)`
    for a bare array, `(True, "items")` for an object with an `items` array."""
    for status in sorted(responses):
        if not status.startswith("2"):
            continue
        content = responses[status]
        if not isinstance(content, dict):
            continue
        for media in sorted(content):
            if not _is_json(media):
                continue
            schema = resolve_ref(document, content[media])
            if _is_array(schema):
                return True, None
            properties = schema.get("properties") if isinstance(schema, dict) else None
            if not isinstance(properties, dict):
                continue
            for name in sorted(properties):
                if _is_array(resolve_ref(document, properties[name])):
                    return True, name
    return False, None


def needs_document(responses: Mapping[str, Any]) -> bool:
    """Whether a stored `responses` holds a `$ref` that only the document can resolve."""
    return '"$ref"' in json.dumps(responses)


# ------------------------------------------------------------------ the answers


def _identifier(element: Any) -> str | None:
    if not isinstance(element, dict):
        return None
    value = element.get("id")
    if isinstance(value, bool) or not isinstance(value, str | int):
        return None
    text = str(value)
    if not text or len(text) > MAX_VALUE_LENGTH or _CONTROL.search(text):
        return None
    return text


def identifiers(body: bytes, array_field: str | None) -> list[str]:
    """The `id` of each element of a listing answer, in order and without repeats."""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return []
    if isinstance(data, dict):
        named = data.get(array_field) if array_field is not None else None
        # The declared field first; otherwise the first array the answer has.
        data = (
            named
            if isinstance(named, list)
            else next((v for v in data.values() if isinstance(v, list)), None)
        )
    if not isinstance(data, list):
        return []
    result: list[str] = []
    for element in data:
        value = _identifier(element)
        if value is not None and value not in result:
            result.append(value)
    return result


# ------------------------------------------------------------------ the requests


class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.sent = 0

    def take(self) -> bool:
        if self.sent >= self.limit:
            return False
        self.sent += 1
        return True


class _OutOfBudgetError(Exception):
    pass


class ResourceDiscoverer:
    """The production discoverer. `address_policy` exists only for tests."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        own_addresses: Iterable[IPAddress] = (),
        address_policy: Callable[[IPAddress], bool] | None = None,
        timeout: float = TIMEOUT_SECONDS,
        max_requests: int = MAX_REQUESTS,
    ) -> None:
        self._resolver = resolver
        self._own_addresses = tuple(own_addresses)
        self._address_policy = address_policy
        self._timeout = timeout
        self._max_requests = max_requests

    async def discover(
        self, host: str, operations: list[ListOperation], searchers: list[Searcher]
    ) -> DiscoveryResult:
        result = DiscoveryResult([IdentityFindings(s.identity_id) for s in searchers])
        budget = _Budget(self._max_requests)
        client = SafeHttpClient(
            host,
            resolver=self._resolver,
            own_addresses=self._own_addresses,
            limits=PROBE_LIMITS,
            address_policy=self._address_policy,
        )
        try:
            async with asyncio.timeout(self._timeout), client:
                for searcher, findings in zip(searchers, result.identities, strict=True):
                    if budget.sent >= budget.limit:
                        result.truncated = True
                        break
                    await self._search(client, budget, operations, searcher, findings)
        except (TimeoutError, _OutOfBudgetError):
            result.truncated = True
        result.requests_sent = budget.sent
        return result

    async def _search(
        self,
        client: SafeHttpClient,
        budget: _Budget,
        operations: list[ListOperation],
        searcher: Searcher,
        findings: IdentityFindings,
    ) -> None:
        # `not_attempted` until a listing answers: a cap reached before that leaves it so, and one
        # reached afterwards keeps what was found with no failure.
        try:
            token = None
            if searcher.auth_type == AuthType.LOGIN:
                if searcher.login is None:
                    findings.failure = DiscoveryFailure.LOGIN_FAILED
                    return
                if not budget.take():
                    raise _OutOfBudgetError()
                _, token = await log_in(client, searcher.login, searcher.credential)
                if token is None:
                    findings.failure = DiscoveryFailure.LOGIN_FAILED
                    return
            headers = credential_headers(
                searcher.auth_type, searcher.credential, searcher.field_name, token
            )
            for operation in operations:
                if not budget.take():
                    raise _OutOfBudgetError()
                try:
                    response = await client.request(
                        "GET",
                        operation.url,
                        headers={**headers, b"Accept": b"application/json"},
                        follow_redirects=False,
                    )
                except ResponseTooLargeError:
                    continue  # an answer, but not one to read
                if not 200 <= response.status_code < 300:
                    continue
                findings.failure = None
                for value in identifiers(response.content, operation.array_field):
                    findings.add(operation.resource_type, value)
            if findings.failure == DiscoveryFailure.NOT_ATTEMPTED:
                findings.failure = DiscoveryFailure.REJECTED  # every listing answered non-2xx
        except DestinationBlockedError as error:
            findings.failure = (
                DiscoveryFailure.CONNECTION_ERROR
                if error.reason == BlockReason.UNRESOLVED
                else DiscoveryFailure.DESTINATION_NOT_ALLOWED  # logged by safe_http
            )
        except (NetworkError, InvalidUrl):
            findings.failure = DiscoveryFailure.CONNECTION_ERROR
