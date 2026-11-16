"""Integration tests run against a real PostgreSQL (RLS cannot be tested on SQLite).

They need `HINDAMA_TEST_DATABASE_URL`, pointing to the `hindama_test` database as `hindama_api`.
Without it they are skipped, so the unit suite still runs without Docker.
"""

import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from hindama.config import Settings
from hindama.models import User
from hindama.models.base import new_id
from tests.conftest import make_settings
from tests.tokens import FakeUserPool

TERMS = "2026-10-30"

TEST_DATABASE_URL = os.environ.get("HINDAMA_TEST_DATABASE_URL")
OWNER_URL = os.environ.get("HINDAMA_TEST_OWNER_DATABASE_URL")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/integration" in str(item.path):
            item.add_marker(pytest.mark.integration)
            if not TEST_DATABASE_URL:
                item.add_marker(pytest.mark.skip(reason="HINDAMA_TEST_DATABASE_URL is not set"))


@pytest.fixture
def settings() -> Settings:
    assert TEST_DATABASE_URL is not None
    return make_settings(TEST_DATABASE_URL)


@pytest.fixture(scope="session")
async def owner() -> AsyncIterator[AsyncEngine]:
    """The schema owner: RLS does not filter it. Used to prepare and inspect data."""
    if not OWNER_URL:
        pytest.skip("HINDAMA_TEST_OWNER_DATABASE_URL is not set")
    engine = create_async_engine(OWNER_URL)
    yield engine
    await engine.dispose()


# ------------------------------------------------------------------ analysts


class Analyst:
    """What Next.js sends on behalf of one Cognito user."""

    def __init__(self, client: httpx.AsyncClient, user_pool: FakeUserPool, sub: str) -> None:
        self.client = client
        self.sub = sub
        self.headers = {"Authorization": f"Bearer {user_pool.token(sub=sub)}"}

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return await self.client.request(method, path, headers=self.headers, **kwargs)

    async def accept_terms(self) -> None:
        response = await self.request("POST", "/me/terms", json={"version": TERMS})
        assert response.status_code == 200

    async def create(self, **fields: Any) -> dict[str, Any]:
        body = {"name": "API de pedidos", "base_url": "https://api.ejemplo.com/v1", **fields}
        response = await self.request("POST", "/projects", json=body)
        assert response.status_code == 201, response.text
        project: dict[str, Any] = response.json()
        return project


@pytest.fixture
async def subs(owner: AsyncEngine) -> AsyncIterator[list[str]]:
    created: list[str] = []
    yield created
    async with owner.begin() as connection:
        await connection.execute(delete(User).where(User.cognito_sub.in_(created)))


@pytest.fixture
def new_analyst(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool, subs: list[str]
) -> Any:
    def make() -> Analyst:
        sub = str(new_id())
        subs.append(sub)
        return Analyst(anonymous_client, user_pool, sub)

    return make


@pytest.fixture
async def ana(new_analyst: Any) -> Analyst:
    analyst: Analyst = new_analyst()
    await analyst.accept_terms()
    return analyst
