from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from hindama.config import Settings
from hindama.main import create_app


@pytest.fixture
def settings() -> Settings:
    # The engine is lazy: unit tests never connect to this database.
    return Settings(
        environment="test",
        database_url=SecretStr("postgresql+asyncpg://test:test@localhost:1/unused"),
        log_format="console",
    )


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
