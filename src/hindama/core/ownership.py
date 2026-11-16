"""Ownership verification: is the project's code on its host? (CU-07; RF-18, RF-21, RN-01).

Valid only for the exact host of the base URL, never its parent domain or a sibling (arquitectura
4.2). Two methods:

- **file:** one GET of `/.well-known/hindama-verificacion.txt` through `SafeHttpClient`, bound to
  the host, with the scheme and port of the base URL, small timeouts and a 1 KiB limit (RN-01: no
  credentials, size and time bounded, through the SSRF guard).
- **dns:** the TXT records of `_hindama-verificacion.<host>`, asked to the system's DNS resolvers.
  It never connects to the user's host, so there is nothing for the SSRF guard to check.

The code is compared in constant time. What was found goes back to the analyst as untrusted text
(`found`), cut to 200 characters and without control characters.
"""

import asyncio
import hmac
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.rdtypes.ANY.TXT
import dns.resolver

from hindama.core.destinations import IPAddress, Resolver
from hindama.core.safe_http import (
    BlockReason,
    DestinationBlockedError,
    Limits,
    NetworkError,
    ResponseTooLargeError,
    SafeHttpClient,
)
from hindama.models.enums import VerificationMethod

FILE_PATH = "/.well-known/hindama-verificacion.txt"
DNS_PREFIX = "_hindama-verificacion."
CODE_PREFIX = "hindama-verificacion="
FILE_LIMITS = Limits(
    connect_timeout=5.0, read_timeout=5.0, max_redirects=3, max_response_bytes=1024
)
DNS_TIMEOUT_SECONDS = 5.0
# The contract promises an answer within 20 seconds, whatever the redirects and retries add up to.
CHECK_TIMEOUT_SECONDS = 15.0
FOUND_MAX_LENGTH = 200


def published_code(verification_code: str) -> str:
    """What the analyst publishes (RF-17): the project's random code, with a recognizable prefix."""
    return f"{CODE_PREFIX}{verification_code}"


def file_url(base_url: str) -> str:
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}{FILE_PATH}"


def dns_name(host: str) -> str:
    return f"{DNS_PREFIX}{host}"


class Outcome(StrEnum):
    """The result; every value but `verified` is a `verification.*` error code of the contract."""

    VERIFIED = "verified"
    FILE_NOT_FOUND = "file_not_found"
    CONTENT_MISMATCH = "content_mismatch"
    TXT_MISSING = "txt_missing"
    CONNECTION_ERROR = "connection_error"
    DESTINATION_NOT_ALLOWED = "destination_not_allowed"


@dataclass(frozen=True, slots=True)
class CheckResult:
    outcome: Outcome
    found: str | None = None


def summarize(text: str) -> str:
    """Untrusted text for `found`: printable characters only, at most 200."""
    clean = "".join(c if c.isprintable() else " " for c in text).strip()
    if len(clean) > FOUND_MAX_LENGTH:
        return clean[: FOUND_MAX_LENGTH - 1] + "…"
    return clean


def _matches(candidate: str, code: str) -> bool:
    return hmac.compare_digest(candidate.encode(), code.encode())


# ---------------------------------------------------------------- DNS


class TxtLookupError(Exception):
    """The DNS did not answer (timeout, no reachable server): not the same as "no record"."""


class TxtResolver(Protocol):
    async def txt(self, name: str) -> list[str]:
        """The TXT records of `name`, each one with its strings joined; [] if there are none."""
        ...


class SystemTxtResolver:
    """dnspython over the system's resolvers, with a total time limit."""

    def __init__(self, timeout: float = DNS_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    async def txt(self, name: str) -> list[str]:
        resolver = dns.asyncresolver.Resolver()
        try:
            answer = await resolver.resolve(name, "TXT", lifetime=self._timeout, search=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as error:
            raise TxtLookupError(name) from error
        return [
            b"".join(record.strings).decode("utf-8", errors="replace")
            for record in answer
            if isinstance(record, dns.rdtypes.ANY.TXT.TXT)
        ]


# ---------------------------------------------------------------- checker


class OwnershipChecker(Protocol):
    async def check(
        self, method: VerificationMethod, *, base_url: str, host: str, code: str
    ) -> CheckResult: ...


class NetworkOwnershipChecker:
    """The production checker. `ssl_context` and `address_policy` exist only for tests."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        txt_resolver: TxtResolver,
        own_addresses: Iterable[IPAddress] = (),
        ssl_context: ssl.SSLContext | None = None,
        address_policy: Callable[[IPAddress], bool] | None = None,
    ) -> None:
        self._resolver = resolver
        self._txt_resolver = txt_resolver
        self._own_addresses = tuple(own_addresses)
        self._ssl_context = ssl_context
        self._address_policy = address_policy

    async def check(
        self, method: VerificationMethod, *, base_url: str, host: str, code: str
    ) -> CheckResult:
        try:
            async with asyncio.timeout(CHECK_TIMEOUT_SECONDS):
                if method == VerificationMethod.FILE:
                    return await self._file(base_url, host, code)
                return await self._dns(host, code)
        except TimeoutError:
            return CheckResult(Outcome.CONNECTION_ERROR)

    async def _file(self, base_url: str, host: str, code: str) -> CheckResult:
        client = SafeHttpClient(
            host,
            resolver=self._resolver,
            own_addresses=self._own_addresses,
            limits=FILE_LIMITS,
            ssl_context=self._ssl_context,
            address_policy=self._address_policy,
        )
        try:
            async with client:
                response = await client.get(file_url(base_url))
        except DestinationBlockedError as error:
            if error.reason == BlockReason.UNRESOLVED:  # the name does not exist: nothing to block
                return CheckResult(Outcome.CONNECTION_ERROR)
            return CheckResult(Outcome.DESTINATION_NOT_ALLOWED)  # already logged by safe_http
        except ResponseTooLargeError as error:
            if 200 <= error.status_code < 300:
                return CheckResult(
                    Outcome.CONTENT_MISMATCH, f"HTTP {error.status_code}: más de 1 KiB"
                )
            return CheckResult(Outcome.FILE_NOT_FOUND, f"HTTP {error.status_code}")
        except NetworkError:
            return CheckResult(Outcome.CONNECTION_ERROR)

        status = response.status_code
        if not 200 <= status < 300:
            return CheckResult(Outcome.FILE_NOT_FOUND, f"HTTP {status}")
        content = response.content.decode("utf-8", errors="replace").strip().lstrip("﻿")
        if _matches(content.strip(), code):
            return CheckResult(Outcome.VERIFIED)
        return CheckResult(Outcome.CONTENT_MISMATCH, summarize(f"HTTP {status}: {content}"))

    async def _dns(self, host: str, code: str) -> CheckResult:
        try:
            records = await self._txt_resolver.txt(dns_name(host))
        except TxtLookupError:
            return CheckResult(Outcome.CONNECTION_ERROR)
        # Every record is compared: no early exit that would tell which one matched by its timing.
        matches = [_matches(record.strip(), code) for record in records]
        if any(matches):
            return CheckResult(Outcome.VERIFIED)
        return CheckResult(Outcome.TXT_MISSING, summarize("; ".join(records)) if records else None)
