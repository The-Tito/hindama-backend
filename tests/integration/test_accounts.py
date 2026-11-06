"""`GET /me` and `POST /me/terms` (CU-02, RF-16, RN-12), against PostgreSQL as `hindama_api`."""

from collections.abc import AsyncIterator
from datetime import datetime
from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.models import User
from hindama.models.base import new_id
from tests.tokens import ADMIN_GROUP, FakeUserPool

CURRENT = "2026-10-30"


@pytest.fixture
async def sub(owner: AsyncEngine) -> AsyncIterator[str]:
    """A fresh Cognito user; its row is deleted afterwards."""
    value = str(new_id())
    yield value
    async with owner.begin() as connection:
        await connection.execute(delete(User).where(User.cognito_sub == value))


@pytest.fixture
def session(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, sub: str
) -> httpx.AsyncClient:
    anonymous_client.headers["Authorization"] = f"Bearer {user_pool.token(sub=sub)}"
    return anonymous_client


async def stored_terms(owner: AsyncEngine, sub: str) -> tuple[str | None, datetime | None]:
    async with owner.connect() as connection:
        row = (
            await connection.execute(
                select(User.terms_version, User.terms_accepted_at).where(User.cognito_sub == sub)
            )
        ).one()
    return row.terms_version, row.terms_accepted_at


async def test_me_registers_the_user_and_reads_the_profile_from_cognito(
    session: httpx.AsyncClient, user_pool: FakeUserPool, owner: AsyncEngine, sub: str
) -> None:
    user_pool.attributes[sub] = {"name": "Ana López", "email": "ana@ejemplo.com"}

    response = await session.get("/me")

    assert response.status_code == 200
    body = response.json()
    async with owner.connect() as connection:
        user_id = await connection.scalar(select(User.id).where(User.cognito_sub == sub))
    assert body == {
        "id": str(user_id),
        "name": "Ana López",
        "email": "ana@ejemplo.com",
        "role": "analyst",
        "terms": {
            "current_version": CURRENT,
            "accepted_version": None,
            "accepted_at": None,
            "acceptance_required": True,
        },
    }


async def test_me_of_an_administrator(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, sub: str
) -> None:
    token = user_pool.token(sub=sub, groups=[ADMIN_GROUP])

    response = await anonymous_client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["role"] == "admin"


async def test_accepting_the_current_terms(
    session: httpx.AsyncClient, owner: AsyncEngine, sub: str
) -> None:
    accepted = await session.post("/me/terms", json={"version": CURRENT})

    assert accepted.status_code == 200
    terms = accepted.json()["terms"]
    assert terms["accepted_version"] == CURRENT
    assert terms["acceptance_required"] is False
    version, accepted_at = await stored_terms(owner, sub)
    assert version == CURRENT
    assert accepted_at is not None
    assert datetime.fromisoformat(terms["accepted_at"]) == accepted_at
    assert (await session.get("/me")).json()["terms"] == terms


async def test_accepting_the_same_version_again_changes_nothing(
    session: httpx.AsyncClient, owner: AsyncEngine, sub: str
) -> None:
    await session.post("/me/terms", json={"version": CURRENT})
    first = await stored_terms(owner, sub)

    again = await session.post("/me/terms", json={"version": CURRENT})

    assert again.status_code == 200
    assert await stored_terms(owner, sub) == first


async def test_an_outdated_version_is_rejected(
    session: httpx.AsyncClient, owner: AsyncEngine, sub: str
) -> None:
    await session.get("/me")  # registers the user; a failed request rolls back everything
    response = await session.post("/me/terms", json={"version": "2026-01-01"})

    assert response.status_code == 422
    assert response.json()["code"] == "terms.outdated_version"
    assert await stored_terms(owner, sub) == (None, None)


async def test_a_new_terms_version_asks_for_acceptance_again(
    app: FastAPI, session: httpx.AsyncClient, owner: AsyncEngine, sub: str
) -> None:
    await session.post("/me/terms", json={"version": CURRENT})
    app.state.settings = app.state.settings.model_copy(update={"terms_version": "2026-12-01"})

    terms = (await session.get("/me")).json()["terms"]
    accepted = await session.post("/me/terms", json={"version": "2026-12-01"})

    assert terms["current_version"] == "2026-12-01"
    assert terms["accepted_version"] == CURRENT
    assert terms["acceptance_required"] is True
    assert accepted.json()["terms"]["acceptance_required"] is False
    assert (await stored_terms(owner, sub))[0] == "2026-12-01"


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({}, 422, "validation.failed"),
        ({"version": CURRENT, "accepted": True}, 422, "validation.failed"),
        ({"version": 20261030}, 422, "validation.failed"),
        ({"version": "x" * 51}, 422, "validation.failed"),
        ({"version": "2026-10-30\u0000"}, 422, "validation.failed"),
    ],
)
async def test_invalid_bodies(
    session: httpx.AsyncClient, body: dict[str, object], status: int, code: str
) -> None:
    response = await session.post("/me/terms", json=body)

    assert response.status_code == status
    assert response.json()["code"] == code


async def test_malformed_json(session: httpx.AsyncClient) -> None:
    response = await session.post(
        "/me/terms", content=b"{", headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 400
    assert response.json()["code"] == "request.malformed"


async def test_a_token_revoked_in_cognito_is_unauthenticated(
    session: httpx.AsyncClient, user_pool: FakeUserPool
) -> None:
    user_pool.get_user_response = (400, {"__type": "NotAuthorizedException"})

    response = await session.get("/me")

    assert response.status_code == 401
    assert response.json()["code"] == "auth.invalid_token"
    assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


async def test_cognito_down_is_service_unavailable_and_stores_nothing(
    session: httpx.AsyncClient, user_pool: FakeUserPool, owner: AsyncEngine, sub: str
) -> None:
    await session.get("/me")  # registers the user
    user_pool.get_user_response = (500, {"__type": "InternalErrorException"})

    response = await session.post("/me/terms", json={"version": CURRENT})

    assert response.status_code == 503
    assert response.json()["code"] == "service.unavailable"
    assert await stored_terms(owner, sub) == (None, None)


async def test_without_a_session(anonymous_client: httpx.AsyncClient) -> None:
    for response in (
        await anonymous_client.get("/me"),
        await anonymous_client.post("/me/terms", json={"version": CURRENT}),
    ):
        assert response.status_code == 401
        assert response.json()["code"] == "auth.required"


async def test_the_id_is_the_platform_user_not_the_cognito_sub(
    session: httpx.AsyncClient, sub: str
) -> None:
    user_id = UUID((await session.get("/me")).json()["id"])

    assert str(user_id) != sub
