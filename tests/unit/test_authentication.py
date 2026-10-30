"""Without a valid session nothing else exists (RF-07; convenciones.md sections 3 and 8)."""

import httpx
import pytest
from fastapi import APIRouter, FastAPI, Request

from hindama.api.dependencies import AnyUser
from tests.tokens import FakeUserPool
from tests.unit.test_problems import assert_problem


@pytest.fixture
def app(app: FastAPI) -> FastAPI:
    router = APIRouter()

    @router.get("/whoami")
    async def whoami(request: Request) -> dict[str, str]:
        principal = request.state.principal
        return {"sub": principal.cognito_sub, "role": principal.role}

    app.include_router(router)
    return app


async def test_missing_token_is_401_auth_required(anonymous_client: httpx.AsyncClient) -> None:
    response = await anonymous_client.get("/whoami")

    assert_problem(response, 401, "auth.required")
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "authorization",
    ["Bearer", "Bearer ", "Basic dXNlcjpwYXNz", "Token abc", "Bearer not-a-jwt"],
)
async def test_malformed_authorization_is_401_invalid_token(
    anonymous_client: httpx.AsyncClient, authorization: str
) -> None:
    response = await anonymous_client.get("/whoami", headers={"Authorization": authorization})

    assert_problem(response, 401, "auth.invalid_token")
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'


async def test_expired_token_is_401_invalid_token(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool
) -> None:
    token = user_pool.token(exp=1)
    response = await anonymous_client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert_problem(response, 401, "auth.invalid_token")


async def test_401_comes_before_404_and_405(anonymous_client: httpx.AsyncClient) -> None:
    assert_problem(await anonymous_client.get("/does-not-exist"), 401, "auth.required")
    assert_problem(await anonymous_client.delete("/whoami"), 401, "auth.required")


async def test_with_a_session_missing_routes_are_404(client: httpx.AsyncClient) -> None:
    assert_problem(await client.get("/does-not-exist"), 404, "resource.not_found")


async def test_valid_token_reaches_the_endpoint(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool
) -> None:
    token = user_pool.token(sub="abc-123", groups=["administradores"])
    response = await anonymous_client.get("/whoami", headers={"Authorization": f"bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"sub": "abc-123", "role": "admin"}


async def test_health_needs_no_token(anonymous_client: httpx.AsyncClient, app: FastAPI) -> None:
    response = await anonymous_client.get("/health")

    # Without a database the check fails, but authentication does not stop it.
    assert response.status_code in (200, 503)


async def test_cognito_down_is_503(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool
) -> None:
    user_pool.jwks_available = False
    token = user_pool.token()
    response = await anonymous_client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert_problem(response, 503, "service.unavailable")


async def test_the_token_is_never_logged(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, capsys: pytest.CaptureFixture[str]
) -> None:
    token = user_pool.token(exp=1)
    await anonymous_client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    output = capsys.readouterr()
    assert "invalid_token" in output.out + output.err  # the rejection is logged...
    assert token not in output.out + output.err
    assert token.split(".")[1] not in output.out + output.err  # not even the claims


async def test_database_down_is_503_without_details(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    """The unit settings point to a port where nothing listens (convenciones.md section 8)."""
    router = APIRouter()

    @router.get("/needs-db")
    async def needs_db(user: AnyUser) -> dict[str, str]:
        return {"id": str(user.id)}

    app.include_router(router)
    response = await client.get("/needs-db")

    body = assert_problem(response, 503, "service.unavailable")
    assert "localhost" not in str(body)
