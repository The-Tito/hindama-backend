"""Integration tests run against a real PostgreSQL (RLS cannot be tested on SQLite).

They need `HINDAMA_TEST_DATABASE_URL`, pointing to the `hindama_test` database as `hindama_api`.
Without it they are skipped, so the unit suite still runs without Docker.
"""

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from hindama.config import Settings
from tests.conftest import make_settings

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
