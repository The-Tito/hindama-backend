"""Testing an identity's credential against the analyst's API (RF-30, RF-32; RN-01, RN-11).

Every request goes through `SafeHttpClient`, bound to the project's verified host (ADR-008), and
none follows redirects: a 3xx is an answer, so the credential is never resent to another place.

Automatic login (RF-30): a JSON body with the username and password under the field names the login
operation declares, and the token read from the JSON answer. It is then sent as a Bearer token.
Login forms (`x-www-form-urlencoded`) and session cookies set by the login come with the scanner.

Nothing here logs or returns the credential: only status codes and a failure kind.
"""

import asyncio
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from hindama.core.credentials import Credential
from hindama.core.destinations import IPAddress, Resolver
from hindama.core.safe_http import (
    BlockReason,
    DestinationBlockedError,
    InvalidUrl,
    Limits,
    NetworkError,
    ResponseTooLargeError,
    SafeHttpClient,
)
from hindama.models.enums import AuthType

TEST_TIMEOUT_SECONDS = 20.0  # the whole test, login included (contract, `testIdentity`)
PROBE_LIMITS = Limits(connect_timeout=5.0, read_timeout=10.0, max_response_bytes=1024 * 1024)

# Field names of a login body, in order of preference; the first the schema declares wins.
USERNAME_FIELDS = ("username", "email", "user", "login", "user_name", "correo", "usuario")
PASSWORD_FIELDS = ("password", "pass", "passwd", "contrasena", "contraseña", "clave")
DEFAULT_LOGIN_FIELDS = ("username", "password")
# Where a login answer usually carries the token: top level first, then inside these objects.
TOKEN_FIELDS = ("access_token", "accessToken", "token", "jwt", "id_token", "idToken")
TOKEN_CONTAINERS = ("data", "result", "auth", "tokens")
MAX_TOKEN_LENGTH = 4096


class Failure(StrEnum):
    REJECTED = "rejected"
    LOGIN_FAILED = "login_failed"
    CONNECTION_ERROR = "connection_error"
    DESTINATION_NOT_ALLOWED = "destination_not_allowed"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    status_code: int | None  # of the protected operation, or of the login when that failed
    failure: Failure | None

    @property
    def succeeded(self) -> bool:
        return self.failure is None


@dataclass(frozen=True, slots=True)
class LoginRequest:
    url: str
    username_field: str
    password_field: str


@dataclass(frozen=True, slots=True)
class Probe:
    """What to send. `field_name` names the cookie or header; `login` only with `login`."""

    host: str
    url: str
    auth_type: AuthType
    credential: Credential
    field_name: str | None = None
    login: LoginRequest | None = None


def login_fields(properties: Iterable[str]) -> tuple[str, str]:
    """The username and password fields a login body declares, or the usual names."""
    declared = {name.lower(): name for name in properties}
    username = next((declared[n] for n in USERNAME_FIELDS if n in declared), None)
    password = next((declared[n] for n in PASSWORD_FIELDS if n in declared), None)
    return username or DEFAULT_LOGIN_FIELDS[0], password or DEFAULT_LOGIN_FIELDS[1]


def find_token(body: bytes) -> str | None:
    """The token of a JSON login answer, or `None`."""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    candidates: list[Any] = [data]
    if isinstance(data, dict):
        candidates += [data.get(name) for name in TOKEN_CONTAINERS]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        for name in TOKEN_FIELDS:
            token = candidate.get(name)
            if _usable(token):
                return str(token)
    return None


def _usable(token: object) -> bool:
    return (
        isinstance(token, str)
        and 0 < len(token) <= MAX_TOKEN_LENGTH
        and token.isprintable()
        and token.strip() == token
    )


class IncompleteCredentialError(Exception):
    """The stored credential lacks what its `auth_type` needs: a bug, never the analyst's input."""


def credential_headers(
    auth_type: AuthType, credential: Credential, field_name: str | None, token: str | None = None
) -> dict[bytes, bytes]:
    """As UTF-8 bytes: httpx would refuse (a 500) a non-ASCII `str` header value."""
    if auth_type == AuthType.LOGIN and token is not None:
        return {b"Authorization": b"Bearer " + token.encode()}
    if auth_type == AuthType.BEARER and credential.token is not None:
        return {b"Authorization": b"Bearer " + credential.token.encode()}
    if field_name is not None and credential.value is not None:
        if auth_type == AuthType.COOKIE:
            return {b"Cookie": f"{field_name}={credential.value}".encode()}
        if auth_type == AuthType.HEADER:
            return {field_name.encode(): credential.value.encode()}
    raise IncompleteCredentialError()


async def log_in(
    client: SafeHttpClient, login: LoginRequest, credential: Credential
) -> tuple[int, str | None]:
    """RF-30: posts the username and password as JSON; returns the status and the token found.
    Shared by the identity test and the scanner."""
    body = json.dumps(
        {login.username_field: credential.username, login.password_field: credential.password}
    ).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        response = await client.request(
            "POST", login.url, headers=headers, content=body, follow_redirects=False
        )
    except ResponseTooLargeError as error:
        return error.status_code, None
    if not 200 <= response.status_code < 300:
        return response.status_code, None
    return response.status_code, find_token(response.content)


class IdentityProber:
    """The production prober. `address_policy` and `ssl_context` exist only for tests."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        own_addresses: Iterable[IPAddress] = (),
        address_policy: Callable[[IPAddress], bool] | None = None,
        timeout: float = TEST_TIMEOUT_SECONDS,
    ) -> None:
        self._resolver = resolver
        self._own_addresses = tuple(own_addresses)
        self._address_policy = address_policy
        self._timeout = timeout

    async def probe(self, probe: Probe) -> ProbeResult:
        client = SafeHttpClient(
            probe.host,
            resolver=self._resolver,
            own_addresses=self._own_addresses,
            limits=PROBE_LIMITS,
            address_policy=self._address_policy,
        )
        try:
            async with asyncio.timeout(self._timeout), client:
                return await self._run(client, probe)
        except DestinationBlockedError as error:
            if error.reason == BlockReason.UNRESOLVED:  # nothing to block: the name does not exist
                return ProbeResult(None, Failure.CONNECTION_ERROR)
            return ProbeResult(None, Failure.DESTINATION_NOT_ALLOWED)  # logged by safe_http
        except (NetworkError, InvalidUrl, TimeoutError):
            return ProbeResult(None, Failure.CONNECTION_ERROR)

    async def _run(self, client: SafeHttpClient, probe: Probe) -> ProbeResult:
        token = None
        if probe.auth_type == AuthType.LOGIN:
            if probe.login is None:
                raise IncompleteCredentialError()
            status, token = await log_in(client, probe.login, probe.credential)
            if token is None:
                return ProbeResult(status, Failure.LOGIN_FAILED)
        headers = credential_headers(probe.auth_type, probe.credential, probe.field_name, token)
        status = await self._status(client, "GET", probe.url, headers)
        return ProbeResult(status, None if 200 <= status < 300 else Failure.REJECTED)

    @staticmethod
    async def _status(
        client: SafeHttpClient, method: str, url: str, headers: Mapping[bytes, bytes]
    ) -> int:
        try:
            response = await client.request(
                method,
                url,
                headers=headers,
                follow_redirects=False,
            )
        except ResponseTooLargeError as error:
            return error.status_code  # an answer all the same; its body is not needed
        return response.status_code
