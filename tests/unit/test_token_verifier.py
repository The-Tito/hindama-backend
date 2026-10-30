"""Cognito access token validation (RF-07, RN-04; convenciones.md section 3)."""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from hindama.core import auth
from hindama.core.auth import InvalidTokenError, Principal, Role
from hindama.core.errors import ServiceUnavailableError
from tests.tokens import ISSUER, FakeUserPool


async def test_valid_access_token_gives_an_analyst(user_pool: FakeUserPool) -> None:
    principal = await user_pool.verifier().verify(user_pool.token(sub="abc-123"))

    assert principal == Principal(cognito_sub="abc-123", role=Role.ANALYST)


async def test_role_comes_from_the_admin_group(user_pool: FakeUserPool) -> None:
    verifier = user_pool.verifier()

    admin = await verifier.verify(user_pool.token(groups=["administradores"]))
    other = await verifier.verify(user_pool.token(groups=["otros", "administradores-falsos"]))

    assert admin.role is Role.ADMIN
    assert other.role is Role.ANALYST


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": int(time.time()) - 60},  # expired
        {"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OtherPool"},
        {"client_id": "otherclient"},  # token of another app client
        {"token_use": "id"},  # an id token is not an access token
        {"sub": None},
        {"client_id": None},
        {"token_use": None},
        {"exp": None},
        {"iat": None},
        {"cognito:groups": "administradores"},  # must be a list
    ],
    ids=lambda claims: ",".join(f"{k}={v}" for k, v in claims.items()),
)
async def test_rejects_tokens_with_wrong_claims(
    user_pool: FakeUserPool, claims: dict[str, Any]
) -> None:
    with pytest.raises(InvalidTokenError):
        await user_pool.verifier().verify(user_pool.token(**claims))


async def test_rejects_a_signature_of_another_key(user_pool: FakeUserPool) -> None:
    forger = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(InvalidTokenError):
        await user_pool.verifier().verify(user_pool.token(key=forger))


async def test_rejects_unsigned_and_symmetric_tokens(user_pool: FakeUserPool) -> None:
    """Algorithm confusion: `alg: none`, and HS256 keyed with the public key."""
    verifier = user_pool.verifier()
    claims = jwt.decode(user_pool.token(), options={"verify_signature": False})
    unsigned = jwt.encode(claims, "", algorithm="none", headers={"kid": user_pool.kid})

    for token in (unsigned, forge_hs256(claims, user_pool)):
        with pytest.raises(InvalidTokenError):
            await verifier.verify(token)


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "x" * 5000])
async def test_rejects_garbage(user_pool: FakeUserPool, token: str) -> None:
    with pytest.raises(InvalidTokenError):
        await user_pool.verifier().verify(token)


async def test_keys_are_cached(user_pool: FakeUserPool) -> None:
    verifier = user_pool.verifier()

    for _ in range(3):
        await verifier.verify(user_pool.token())

    assert user_pool.jwks_requests == 1


async def test_key_rotation_refreshes_the_keys(
    user_pool: FakeUserPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = user_pool.verifier()
    await verifier.verify(user_pool.token())
    user_pool.rotate_key()

    # Right after a download, an unknown kid does not trigger another one...
    with pytest.raises(InvalidTokenError):
        await verifier.verify(user_pool.token())
    assert user_pool.jwks_requests == 1

    # ...but once the minimum interval passes, it does.
    monkeypatch.setattr(auth, "MIN_REFRESH_INTERVAL_SECONDS", 0)
    assert await verifier.verify(user_pool.token())
    assert user_pool.jwks_requests == 2


async def test_unknown_kids_cannot_flood_cognito(user_pool: FakeUserPool) -> None:
    verifier = user_pool.verifier()
    await verifier.verify(user_pool.token())

    for attempt in range(20):
        with pytest.raises(InvalidTokenError):
            await verifier.verify(user_pool.token(kid=f"random-{attempt}"))

    assert user_pool.jwks_requests == 1


async def test_without_keys_cognito_down_is_503(user_pool: FakeUserPool) -> None:
    user_pool.jwks_available = False

    with pytest.raises(ServiceUnavailableError):
        await user_pool.verifier().verify(user_pool.token())


async def test_cached_keys_keep_working_while_cognito_is_down(
    user_pool: FakeUserPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = user_pool.verifier()
    await verifier.verify(user_pool.token())
    user_pool.jwks_available = False
    monkeypatch.setattr(auth, "MIN_REFRESH_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(verifier, "_cache_seconds", 0)  # the cache has expired

    assert await verifier.verify(user_pool.token())


def forge_hs256(claims: dict[str, Any], user_pool: FakeUserPool) -> str:
    """HS256 token whose HMAC secret is the pool's public JWK, as a confused verifier would use.

    Built by hand because PyJWT refuses to sign HS256 with a public key.
    """

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": user_pool.kid}).encode())
    payload = b64(json.dumps({**claims, "iss": ISSUER}).encode())
    secret = json.dumps(user_pool.jwks()["keys"][0]).encode()
    signature = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(signature)}"
