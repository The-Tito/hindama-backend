"""Async engine and sessions (SQLAlchemy 2 + asyncpg, ADR-012)."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

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


async def set_rls_context(
    session: AsyncSession, *, cognito_sub: str, role: str, user_id: UUID | None = None
) -> None:
    """Fixes the Row-Level Security settings for the current transaction only (ADR-013).

    The third argument of set_config, `true`, scopes them to the transaction: when the connection
    goes back to the pool no user remains set (tests/integration/test_database_security.py).
    """
    await session.execute(
        text(
            "SELECT set_config('app.cognito_sub', :sub, true),"
            " set_config('app.role', :role, true),"
            " set_config('app.user_id', :user_id, true)"
        ),
        {"sub": cognito_sub, "role": role, "user_id": str(user_id) if user_id else ""},
    )
