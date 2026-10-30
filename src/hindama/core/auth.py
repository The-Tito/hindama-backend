"""Validation of Cognito access tokens (RF-07) and the role of the caller (RN-04).

FastAPI trusts nothing that Next.js sends except a token signed by Cognito: the signature is checked
with the User Pool keys (JWKS), and then `iss`, `token_use = access`, `client_id` and `exp`
(convenciones.md, section 3). The role comes only from the `cognito:groups` claim.
"""

import asyncio
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID

import httpx
import jwt
import structlog

from hindama.core.errors import ServiceUnavailableError

log = structlog.get_logger("hindama.auth")

# Cognito signs with RS256 only. Fixing the list blocks `alg: none` and HS256-with-the-public-key.
ALGORITHMS = ["RS256"]
ACCESS_TOKEN_USE = "access"  # noqa: S105 - a claim value, not a secret
MAX_TOKEN_LENGTH = 4096  # Cognito access tokens are ~1 KB; anything bigger is not one of them
CLOCK_LEEWAY_SECONDS = 10
# An unknown `kid` forces a refresh (key rotation), at most this often: random kids cannot make
# the API hammer Cognito.
MIN_REFRESH_INTERVAL_SECONDS = 60


class Role(StrEnum):
    ANALYST = "analyst"
    ADMIN = "admin"


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller, as stated by a valid token."""

    cognito_sub: str
    role: Role


@dataclass(frozen=True, slots=True)
class CurrentUser:
    """The caller once matched to its `users` row."""

    id: UUID
    cognito_sub: str
    role: Role


class InvalidTokenError(Exception):
    """The token is malformed, expired, forged or not an access token of this client.

    The reason is only logged; the client always gets the same `auth.invalid_token`.
    """


class TokenVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        admin_group: str,
        jwks_url: str,
        http: httpx.AsyncClient,
        cache_seconds: int = 3600,
    ) -> None:
        self._issuer = issuer
        self._client_id = client_id
        self._admin_group = admin_group
        self._jwks_url = jwks_url
        self._http = http
        self._cache_seconds = cache_seconds
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float | None = None  # last successful download
        self._attempted_at: float | None = None  # last download attempt, successful or not
        self._lock = asyncio.Lock()

    async def verify(self, token: str) -> Principal:
        if len(token) > MAX_TOKEN_LENGTH:
            raise InvalidTokenError("too long")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as error:
            raise InvalidTokenError("malformed header") from error
        kid = header.get("kid")
        if header.get("alg") not in ALGORITHMS or not isinstance(kid, str):
            raise InvalidTokenError("unexpected alg or kid")

        key = await self._key(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=ALGORITHMS,
                issuer=self._issuer,
                leeway=CLOCK_LEEWAY_SECONDS,
                # Access tokens have no `aud`; their audience is `client_id`, checked below.
                options={
                    "require": ["exp", "iat", "iss", "sub", "token_use", "client_id"],
                    "verify_aud": False,
                },
            )
        except jwt.InvalidTokenError as error:
            raise InvalidTokenError(type(error).__name__) from error

        if claims["token_use"] != ACCESS_TOKEN_USE:  # an id token must not open the API
            raise InvalidTokenError("not an access token")
        if claims["client_id"] != self._client_id:
            raise InvalidTokenError("other client")
        sub = claims["sub"]
        groups = claims.get("cognito:groups", [])
        if not isinstance(sub, str) or not sub or not isinstance(groups, list):
            raise InvalidTokenError("unexpected claim types")

        role = Role.ADMIN if self._admin_group in groups else Role.ANALYST
        return Principal(cognito_sub=sub, role=role)

    async def _key(self, kid: str) -> jwt.PyJWK:
        if self._is_fresh() and kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            # Another request may have refreshed the keys while this one waited.
            if kid not in self._keys or not self._is_fresh():
                if self._may_refresh():
                    await self._refresh()
                elif not self._keys:
                    raise ServiceUnavailableError()
        if kid not in self._keys:
            raise InvalidTokenError("unknown kid")
        return self._keys[kid]

    def _is_fresh(self) -> bool:
        return (
            self._fetched_at is not None
            and time.monotonic() - self._fetched_at < self._cache_seconds
        )

    def _may_refresh(self) -> bool:
        return (
            self._attempted_at is None
            or time.monotonic() - self._attempted_at >= MIN_REFRESH_INTERVAL_SECONDS
        )

    async def _refresh(self) -> None:
        self._attempted_at = time.monotonic()
        try:
            response = await self._http.get(self._jwks_url)
            response.raise_for_status()
            key_set = jwt.PyJWKSet.from_dict(response.json())
        except (httpx.HTTPError, ValueError, jwt.PyJWKSetError) as error:
            log.warning("jwks_unavailable", error=type(error).__name__)
            # Expired keys still verify tokens while Cognito does not answer; without any, 503.
            if not self._keys:
                raise ServiceUnavailableError() from error
            return
        self._keys = {key.key_id: key for key in key_set.keys if key.key_id}
        self._fetched_at = time.monotonic()
