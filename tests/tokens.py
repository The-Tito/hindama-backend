"""A fake Cognito User Pool: signing keys, its JWKS endpoint and access tokens."""

import json
import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from hindama.core.auth import TokenVerifier

REGION = "us-east-1"
USER_POOL_ID = "us-east-1_TestPool1"
CLIENT_ID = "hindamatestclient"
ADMIN_GROUP = "administradores"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"


class FakeUserPool:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "test-key-1"
        self.jwks_requests = 0
        self.jwks_available = True

    def jwks(self) -> dict[str, Any]:
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {"keys": [{**public, "kid": self.kid, "alg": "RS256", "use": "sig"}]}

    def rotate_key(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = f"{self.kid}-rotated"

    def token(
        self,
        sub: str = "0192e3a0-aaaa-7000-8000-000000000001",
        groups: list[str] | None = None,
        *,
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = None,
        **claims: Any,
    ) -> str:
        """An access token as Cognito issues it; `claims` override or remove (None) any claim."""
        now = int(time.time())
        payload: dict[str, Any] = {
            "sub": sub,
            "iss": ISSUER,
            "client_id": CLIENT_ID,
            "token_use": "access",
            "scope": "aws.cognito.signin.user.admin",
            "auth_time": now,
            "iat": now,
            "exp": now + 3600,
            "jti": "a1b2c3",
            "username": sub,
        }
        if groups is not None:
            payload["cognito:groups"] = groups
        payload.update(claims)
        payload = {name: value for name, value in payload.items() if value is not None}
        return jwt.encode(
            payload, key or self.key, algorithm="RS256", headers={"kid": kid or self.kid}
        )

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == JWKS_URL
            self.jwks_requests += 1
            if not self.jwks_available:
                return httpx.Response(503)
            return httpx.Response(200, json=self.jwks())

        return httpx.MockTransport(handle)

    def verifier(self) -> TokenVerifier:
        return TokenVerifier(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            admin_group=ADMIN_GROUP,
            jwks_url=JWKS_URL,
            http=httpx.AsyncClient(transport=self.transport()),
        )
