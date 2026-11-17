"""Sends the requests of one run as each identity (RF-29, RF-30, RF-47, RF-50).

- Every request goes through the run's `RequestLimiter` and its `SafeHttpClient`, bound to the
  verified host: the SSRF guard resolves and checks the address before each one.
- Redirects are not followed: the module judges the answer the API gave, and a redirect to another
  host is never reached.
- Automatic login (RF-30): an identity logs in on its first request and again, once, when the API
  answers 401. Concurrent requests of the same identity share one login.
"""

import asyncio
from collections import defaultdict
from uuid import UUID

import structlog

from hindama.core.identity_probe import credential_headers, log_in
from hindama.core.safe_http import (
    DestinationBlockedError,
    InvalidUrl,
    Limits,
    NetworkError,
    ResponseTooLargeError,
    SafeHttpClient,
)
from hindama.models.enums import AuthType
from hindama.scanner.context import Actor
from hindama.scanner.evidence import Exchange, Masker
from hindama.scanner.limiter import RequestLimiter

log = structlog.get_logger(__name__)

# 1 MB is plenty to judge an answer; evidence keeps only 10 KB of it (RF-67).
SCAN_LIMITS = Limits(connect_timeout=5.0, read_timeout=15.0, max_response_bytes=1024 * 1024)


class RequestFailedError(Exception):
    """No usable answer: blocked destination, network error or an oversized body. The cell that
    needed it is recorded as `error`, not the whole run."""


class LoginFailedError(Exception):
    """The identity could not log in: its cells are skipped (RF-30)."""


class Requester:
    def __init__(
        self, client: SafeHttpClient, limiter: RequestLimiter, base_url: str, masker: Masker
    ) -> None:
        self._client = client
        self._limiter = limiter
        self._base_url = base_url
        self.masker = masker
        self._tokens: dict[UUID, str] = {}
        self._logins: defaultdict[UUID, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._login_failed: set[UUID] = set()  # tried once per run: no hammering of the login

    @property
    def sent(self) -> int:
        return self._limiter.sent

    async def send(self, actor: Actor, method: str, path: str) -> Exchange:
        """Raises `RequestFailedError`, `LoginFailedError` and `BudgetExhaustedError`."""
        token = await self._token(actor) if actor.auth_type == AuthType.LOGIN else None
        exchange = await self._send(actor, method, path, token)
        if exchange.status_code == 401 and token is not None:
            token = await self._token(actor, stale=token)  # it may have expired (RF-30)
            exchange = await self._send(actor, method, path, token)
        return exchange

    async def _send(self, actor: Actor, method: str, path: str, token: str | None) -> Exchange:
        headers = {"Accept": "application/json"}
        if actor.credential is not None:
            raw = credential_headers(actor.auth_type, actor.credential, actor.field_name, token)
            headers |= {name.decode(): value.decode() for name, value in raw.items()}
        url = self._base_url + path
        async with self._limiter.slot():
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers={k.encode(): v.encode() for k, v in headers.items()},
                    follow_redirects=False,
                )
            except DestinationBlockedError as error:
                log.warning("scanner_destination_blocked", reason=error.reason.value)
                raise RequestFailedError(error.reason.value) from None
            except ResponseTooLargeError:
                raise RequestFailedError("response_too_large") from None
            except (NetworkError, InvalidUrl) as error:
                raise RequestFailedError(type(error).__name__) from None
        return Exchange(
            method=method,
            url=url,
            request_headers=headers,
            status_code=response.status_code,
            response_headers=tuple(response.headers.items()),
            body=response.content,
        )

    async def _token(self, actor: Actor, stale: str | None = None) -> str:
        async with self._logins[actor.id]:
            if actor.id in self._login_failed:
                raise LoginFailedError()
            current = self._tokens.get(actor.id)
            if current is not None and current != stale:
                return current  # another request already logged in, or renewed it
            if actor.login is None or actor.credential is None:  # context.load leaves them out
                raise LoginFailedError()
            async with self._limiter.slot():
                try:
                    status, token = await log_in(self._client, actor.login, actor.credential)
                except (DestinationBlockedError, NetworkError, InvalidUrl):
                    status, token = None, None
            if token is None:
                log.info("scanner_login_failed", identity_id=str(actor.id), status_code=status)
                self._login_failed.add(actor.id)
                raise LoginFailedError()
            self.masker.add(token)
            self._tokens[actor.id] = token
            return token
