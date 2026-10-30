"""Row-Level Security, privileges and the immutable audit log (modelo.md 5 and 7.4, ADR-013).

This is also the technical proof of ADR-013: connected as `hindama_api`, with the settings fixed by
set_config(..., true) inside the transaction, an analyst neither sees nor writes another analyst's
project, without settings nothing is visible, and the settings do not leak to the next transaction
of the same pooled connection.

The data is committed by the schema owner (RLS does not filter it) and deleted after each test.
Audit log rows are only written inside transactions that are rolled back, because the trigger keeps
recent rows forever.
"""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from hindama.models.base import new_id

API_URL = os.environ.get("HINDAMA_TEST_DATABASE_URL")
OWNER_URL = os.environ.get("HINDAMA_TEST_OWNER_DATABASE_URL")
SCANNER_URL = os.environ.get("HINDAMA_TEST_SCANNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not (API_URL and OWNER_URL and SCANNER_URL),
    reason="HINDAMA_TEST_DATABASE_URL, _OWNER_ and _SCANNER_DATABASE_URL are needed",
)

INSUFFICIENT_PRIVILEGE = "42501"  # missing GRANT, or a row rejected by a policy
RAISE_EXCEPTION = "P0001"  # the audit log trigger


@dataclass(frozen=True)
class Analyst:
    user_id: UUID
    cognito_sub: str
    project_id: UUID
    identity_id: UUID


# ---------------------------------------------------------------- fixtures


@pytest.fixture(scope="session")
async def owner() -> AsyncIterator[AsyncEngine]:
    assert OWNER_URL is not None
    engine = create_async_engine(OWNER_URL)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def api() -> AsyncIterator[AsyncEngine]:
    assert API_URL is not None
    # A single pooled connection, so consecutive transactions surely reuse it.
    engine = create_async_engine(API_URL, pool_size=1, max_overflow=0)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def scanner() -> AsyncIterator[AsyncEngine]:
    assert SCANNER_URL is not None
    engine = create_async_engine(SCANNER_URL)
    yield engine
    await engine.dispose()


async def create_analyst(connection: AsyncConnection) -> Analyst:
    analyst = Analyst(new_id(), str(new_id()), new_id(), new_id())
    await connection.execute(
        text("INSERT INTO users (id, cognito_sub) VALUES (:id, :sub)"),
        {"id": analyst.user_id, "sub": analyst.cognito_sub},
    )
    await connection.execute(
        text(
            "INSERT INTO projects (id, owner_id, name, base_url, host, verification_code)"
            " VALUES (:id, :owner, 'API de pedidos', 'https://api.ejemplo.com', 'api.ejemplo.com',"
            " :code)"
        ),
        {"id": analyst.project_id, "owner": analyst.user_id, "code": str(new_id())},
    )
    await connection.execute(
        text(
            "INSERT INTO identities (id, project_id, name, role, auth_type)"
            " VALUES (:id, :project, 'Anónima', 'user', 'none')"
        ),
        {"id": analyst.identity_id, "project": analyst.project_id},
    )
    return analyst


@pytest.fixture
async def analysts(owner: AsyncEngine) -> AsyncIterator[tuple[Analyst, Analyst]]:
    """Two analysts, each with one project and its anonymous identity."""
    async with owner.begin() as connection:
        alice = await create_analyst(connection)
        bob = await create_analyst(connection)
    yield alice, bob
    async with owner.begin() as connection:
        # Cascades to projects and their content.
        await connection.execute(
            text("DELETE FROM users WHERE id IN (:a, :b)"), {"a": alice.user_id, "b": bob.user_id}
        )


@asynccontextmanager
async def transaction(
    engine: AsyncEngine, analyst: Analyst | None = None, role: str = "analyst"
) -> AsyncIterator[AsyncConnection]:
    """A transaction that is always rolled back, with the RLS settings fixed as the API will."""
    async with engine.connect() as connection:
        await connection.begin()
        try:
            if analyst is not None:
                await connection.execute(
                    text(
                        "SELECT set_config('app.cognito_sub', :sub, true),"
                        " set_config('app.user_id', :user_id, true),"
                        " set_config('app.role', :role, true)"
                    ),
                    {"sub": analyst.cognito_sub, "user_id": str(analyst.user_id), "role": role},
                )
            yield connection
        finally:
            await connection.rollback()


async def ids(connection: AsyncConnection, table: str) -> set[UUID]:
    rows = await connection.execute(text(f"SELECT id FROM {table}"))  # noqa: S608 (constant)
    return set(rows.scalars())


async def sqlstate_of(
    engine: AsyncEngine, statement: str, analyst: Analyst | None = None, **params: Any
) -> str | None:
    """Runs one statement in its own transaction and returns the SQLSTATE it fails with."""
    async with transaction(engine, analyst) as connection:
        try:
            await connection.execute(text(statement), params)
        except DBAPIError as error:
            return getattr(error.orig, "sqlstate", None)
    return None


async def insert_audit_event(connection: AsyncConnection) -> None:
    await connection.execute(text("INSERT INTO audit_log (action) VALUES ('test.event')"))


# ---------------------------------------------------------------- ADR-013: isolation by owner


async def test_analyst_sees_only_own_rows(api: AsyncEngine, analysts: tuple[Analyst, ...]) -> None:
    alice, _ = analysts
    async with transaction(api, alice) as connection:
        assert await ids(connection, "users") == {alice.user_id}
        assert await ids(connection, "projects") == {alice.project_id}
        # Child tables follow the policy of `projects`.
        assert await ids(connection, "identities") == {alice.identity_id}


async def test_without_settings_nothing_is_visible(
    api: AsyncEngine, analysts: tuple[Analyst, ...]
) -> None:
    async with transaction(api) as connection:
        for table in ("users", "projects", "identities"):
            assert await ids(connection, table) == set()


async def test_analyst_cannot_modify_another_project(
    api: AsyncEngine, analysts: tuple[Analyst, ...]
) -> None:
    alice, bob = analysts
    async with transaction(api, alice) as connection:
        for statement in (
            "UPDATE projects SET name = 'mío' WHERE id = :id",
            "DELETE FROM projects WHERE id = :id",
            "UPDATE identities SET name = 'mía' WHERE project_id = :id",
        ):
            result = await connection.execute(text(statement), {"id": bob.project_id})
            assert result.rowcount == 0  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "statement",
    [
        # A row inside another project.
        "INSERT INTO identities (project_id, name, role, auth_type)"
        " VALUES (:other_project, 'Intrusa', 'user', 'bearer')",
        # Giving away an own project, or moving an own row into another project.
        "UPDATE projects SET owner_id = :other_user WHERE id = :own_project",
        "UPDATE identities SET project_id = :other_project WHERE project_id = :own_project",
        # A user row for another Cognito account.
        "INSERT INTO users (cognito_sub) VALUES ('otra-cuenta')",
    ],
)
async def test_policy_rejects_writing_rows_of_another_owner(
    api: AsyncEngine, analysts: tuple[Analyst, ...], statement: str
) -> None:
    alice, bob = analysts
    params = {
        "own_project": alice.project_id,
        "other_project": bob.project_id,
        "other_user": bob.user_id,
    }
    assert await sqlstate_of(api, statement, alice, **params) == INSUFFICIENT_PRIVILEGE


async def test_settings_do_not_leak_to_the_next_transaction(
    api: AsyncEngine, analysts: tuple[Analyst, ...]
) -> None:
    alice, _ = analysts
    async with transaction(api, alice) as connection:
        backend = (await connection.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        assert await ids(connection, "projects") == {alice.project_id}

    # The pool has one connection: this transaction runs on the same backend.
    async with transaction(api) as connection:
        assert (await connection.execute(text("SELECT pg_backend_pid()"))).scalar_one() == backend
        setting = await connection.execute(text("SELECT current_setting('app.user_id', true)"))
        assert setting.scalar_one() in (None, "")
        assert await ids(connection, "projects") == set()


async def test_administrator_sees_no_project(
    api: AsyncEngine, analysts: tuple[Analyst, ...]
) -> None:
    """Even if an endpoint forgot its 403, RLS returns nothing to the administrator (RN-03)."""
    admin = Analyst(new_id(), str(new_id()), new_id(), new_id())  # owns nothing
    async with transaction(api, admin, role="admin") as connection:
        assert await ids(connection, "projects") == set()
        assert await ids(connection, "identities") == set()


# ---------------------------------------------------------------- audit log (RF-82, RF-83)


async def test_only_the_administrator_reads_the_audit_log(
    api: AsyncEngine, analysts: tuple[Analyst, ...]
) -> None:
    alice, _ = analysts
    async with transaction(api, alice) as connection:
        await insert_audit_event(connection)
        count = await connection.execute(text("SELECT count(*) FROM audit_log"))
        assert count.scalar_one() == 0

    async with transaction(api, alice, role="admin") as connection:
        await insert_audit_event(connection)
        count = await connection.execute(text("SELECT count(*) FROM audit_log"))
        assert count.scalar_one() >= 1


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_log SET action = 'otra'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
        # The date is always the database's: no backdating into the purge window.
        "INSERT INTO audit_log (action, occurred_at) VALUES ('test.event', now() - interval '1y')",
        "SELECT purge_audit_log()",
    ],
)
async def test_api_cannot_alter_the_audit_log(
    api: AsyncEngine, analysts: tuple[Analyst, ...], statement: str
) -> None:
    assert await sqlstate_of(api, statement, analysts[0]) == INSUFFICIENT_PRIVILEGE


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_log SET action = 'otra'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
    ],
)
async def test_trigger_protects_recent_events_even_from_the_owner(
    owner: AsyncEngine, statement: str
) -> None:
    async with transaction(owner) as connection:
        await insert_audit_event(connection)
        with pytest.raises(DBAPIError) as error:
            await connection.execute(text(statement))
        assert getattr(error.value.orig, "sqlstate", None) == RAISE_EXCEPTION


async def test_purge_deletes_only_expired_events(owner: AsyncEngine, scanner: AsyncEngine) -> None:
    marker = f"test.purge.{new_id()}"
    async with owner.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO audit_log (action, occurred_at)"
                " VALUES (:a, now() - interval '7 months')"
            ),
            {"a": marker},
        )

    async with scanner.begin() as connection:
        purged = await connection.execute(text("SELECT purge_audit_log()"))
        assert purged.scalar_one() >= 1

    async with transaction(owner) as connection:
        remaining = await connection.execute(
            text("SELECT count(*) FROM audit_log WHERE action = :a"), {"a": marker}
        )
        assert remaining.scalar_one() == 0
        # A recent event survives the purge.
        await insert_audit_event(connection)
        await connection.execute(text("SELECT purge_audit_log()"))
        recent = await connection.execute(
            text("SELECT count(*) FROM audit_log WHERE action = 'test.event'")
        )
        assert recent.scalar_one() == 1


@pytest.mark.parametrize(
    "statement",
    ["UPDATE finding_events SET reason = 'other'", "DELETE FROM finding_events"],
)
async def test_finding_history_is_append_only(
    api: AsyncEngine, analysts: tuple[Analyst, ...], statement: str
) -> None:
    """RF-72: neither application role rewrites the history of a finding."""
    assert await sqlstate_of(api, statement, analysts[0]) == INSUFFICIENT_PRIVILEGE


# ---------------------------------------------------------------- scanner privileges (5.3)


async def test_scanner_reads_every_project(
    scanner: AsyncEngine, analysts: tuple[Analyst, ...]
) -> None:
    alice, bob = analysts
    async with transaction(scanner) as connection:
        assert {alice.project_id, bob.project_id} <= await ids(connection, "projects")


async def test_scanner_updates_verification_and_identity_status(
    scanner: AsyncEngine, analysts: tuple[Analyst, ...]
) -> None:
    alice, _ = analysts
    async with transaction(scanner) as connection:
        project = await connection.execute(
            text(
                "UPDATE projects SET verification_status = 'pending', verified_at = NULL"
                " WHERE id = :id"
            ),
            {"id": alice.project_id},
        )
        identity = await connection.execute(
            text("UPDATE identities SET status = 'expired_credential' WHERE id = :id"),
            {"id": alice.identity_id},
        )
        assert project.rowcount == identity.rowcount == 1  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT id FROM users",
        "SELECT id FROM audit_log",
        "UPDATE projects SET base_url = 'https://otra.com', host = 'otra.com'",
        "UPDATE identities SET name = 'otra'",
        "DELETE FROM projects",
        "DELETE FROM findings",
        "UPDATE finding_events SET reason = 'other'",
        "INSERT INTO runs (project_id, number, config) SELECT id, 99, '{}' FROM projects",
    ],
)
async def test_scanner_privileges_are_limited(
    scanner: AsyncEngine, analysts: tuple[Analyst, ...], statement: str
) -> None:
    assert await sqlstate_of(scanner, statement) == INSUFFICIENT_PRIVILEGE
