"""Integration tests run against a real PostgreSQL (RLS cannot be tested on SQLite).

They need `HINDAMA_TEST_DATABASE_URL`, pointing to the `hindama_test` database as `hindama_api`.
Without it they are skipped, so the unit suite still runs without Docker.
"""

import os

import pytest
from pydantic import SecretStr

from hindama.config import Settings

TEST_DATABASE_URL = os.environ.get("HINDAMA_TEST_DATABASE_URL")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/integration" in str(item.path):
            item.add_marker(pytest.mark.integration)
            if not TEST_DATABASE_URL:
                item.add_marker(pytest.mark.skip(reason="HINDAMA_TEST_DATABASE_URL is not set"))


@pytest.fixture
def settings() -> Settings:
    assert TEST_DATABASE_URL is not None
    return Settings(
        environment="test",
        database_url=SecretStr(TEST_DATABASE_URL),
        log_format="console",
    )
