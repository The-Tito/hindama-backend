"""Async engine and sessions (SQLAlchemy 2 + asyncpg, ADR-012)."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from hindama.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Creates the engine; it does not connect until the first query."""
    return create_async_engine(
        settings.database_url.get_secret_value(),
        pool_size=settings.database_pool_size,
        pool_pre_ping=True,
        # Never log statements: parameters may include encrypted credentials or user data.
        echo=False,
        hide_parameters=True,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker:  # type: ignore[type-arg]
    return async_sessionmaker(engine, expire_on_commit=False)


async def ping(engine: AsyncEngine) -> None:
    """Raises if the database does not answer a trivial query."""
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
