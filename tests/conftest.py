import os
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from hindama.config import Settings
from hindama.main import create_app
from tests.tokens import CLIENT_ID, REGION, USER_POOL_ID, FakeUserPool

# In CI every test must run: a missing variable would otherwise skip the RLS tests silently.
FAIL_ON_SKIP = os.environ.get("HINDAMA_FAIL_ON_SKIP") == "1"
_skipped: list[str] = []


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped:
        _skipped.append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if FAIL_ON_SKIP and _skipped and exitstatus == pytest.ExitCode.OK:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(f"HINDAMA_FAIL_ON_SKIP: {len(_skipped)} pruebas omitidas")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def make_settings(database_url: str) -> Settings:
    return Settings(
        environment="test",
        database_url=SecretStr(database_url),
        log_format="console",
        cognito_region=REGION,
        cognito_user_pool_id=USER_POOL_ID,
        cognito_client_id=CLIENT_ID,
    )


@pytest.fixture
def settings() -> Settings:
    # The engine is lazy: unit tests never connect to this database.
    return make_settings("postgresql+asyncpg://test:test@localhost:1/unused")


@pytest.fixture
def user_pool() -> FakeUserPool:
    return FakeUserPool()


@pytest.fixture
def app(settings: Settings, user_pool: FakeUserPool) -> FastAPI:
    return create_app(settings, verifier=user_pool.verifier())


@pytest.fixture
async def anonymous_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Like Next.js without a session: no Authorization header."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def client(
    anonymous_client: httpx.AsyncClient, user_pool: FakeUserPool
) -> AsyncIterator[httpx.AsyncClient]:
    """An analyst's session: every request carries a valid access token."""
    anonymous_client.headers["Authorization"] = f"Bearer {user_pool.token()}"
    yield anonymous_client
