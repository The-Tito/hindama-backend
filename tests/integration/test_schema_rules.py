"""The database itself enforces the rules of modelo.md, section 5.2.

These tests connect as the schema owner (HINDAMA_TEST_OWNER_DATABASE_URL): they check constraints,
not privileges. Each test runs in a transaction that is rolled back.
"""

import os
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime
from typing import Any

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from hindama.models import (
    ContractVersion,
    Finding,
    FindingEvent,
    FindingMetric,
    FindingOccurrence,
    Identity,
    Operation,
    Project,
    Resource,
    Result,
    Run,
    User,
)
from hindama.models.base import Base, new_id

OWNER_URL = os.environ.get("HINDAMA_TEST_OWNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(not OWNER_URL, reason="HINDAMA_TEST_OWNER_DATABASE_URL is not set")

NOW = datetime(2026, 11, 2, 15, 0, tzinfo=UTC)


@pytest.fixture
async def db() -> AsyncIterator[AsyncSession]:
    assert OWNER_URL is not None
    engine = create_async_engine(OWNER_URL)
    async with engine.connect() as connection:
        transaction = await connection.begin()
        session = AsyncSession(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            await session.close()
            await transaction.rollback()
    await engine.dispose()


async def rejected(db: AsyncSession, *rows: Base) -> bool:
    """True if the database rejects inserting these rows (inside a savepoint)."""
    try:
        async with db.begin_nested():
            db.add_all(rows)
            await db.flush()
    except IntegrityError:
        return True
    return False


async def make_project(db: AsyncSession, name: str = "API de pedidos") -> Project:
    user = User(cognito_sub=str(new_id()))
    db.add(user)
    await db.flush()
    project = Project(
        owner_id=user.id,
        name=name,
        base_url="https://api.ejemplo.com/v1",
        host="api.ejemplo.com",
        verification_code=str(new_id()),
    )
    db.add(project)
    await db.flush()
    return project


def anonymous(project: Project) -> Identity:
    return Identity(project_id=project.id, name="Anónima", role="user", auth_type="none")


def bearer(project: Project, name: str = "Usuario A") -> Identity:
    return Identity(
        project_id=project.id,
        name=name,
        role="user",
        auth_type="bearer",
        encrypted_credential=b"\x01nonce-ciphertext-tag",
        key_version=1,
        credential_suffix="9f2a",
    )


def run(project: Project, number: int = 1, **fields: Any) -> Run:
    return Run(
        project_id=project.id, number=number, config={"modules": ["authentication"]}, **fields
    )


def operation(project: Project, path: str = "/orders/{}") -> Operation:
    return Operation(project_id=project.id, method="GET", normalized_path=path, path=path)


# ---------------------------------------------------------------- RN-07


async def test_only_one_active_run_per_project(db: AsyncSession) -> None:
    project = await make_project(db)
    db.add(run(project, 1))
    await db.flush()

    assert await rejected(db, run(project, 2, status="running"))
    finished = run(project, 3, status="completed", end_reason="normal", finished_at=NOW)
    assert not await rejected(db, finished)


@pytest.mark.parametrize(
    ("status", "end_reason", "finished"),
    [
        ("queued", "normal", False),  # active runs have no end reason
        ("completed", None, True),  # final runs need one
        ("completed", "cancelled_by_user", True),  # and it must match the status
        ("failed", "error", False),  # final runs have finished_at
    ],
)
async def test_end_reason_matches_status(
    db: AsyncSession, status: str, end_reason: str | None, finished: bool
) -> None:
    project = await make_project(db)
    bad = run(project, status=status, end_reason=end_reason, finished_at=NOW if finished else None)

    assert await rejected(db, bad)


# ---------------------------------------------------------------- RN-01, RF-13


async def test_verified_only_for_the_current_host(db: AsyncSession) -> None:
    project = await make_project(db)
    project.verification_status = "verified"
    project.verification_method = "file"
    project.verified_at = NOW
    project.verified_host = "api.ejemplo.com"
    await db.flush()

    project.host = "otro.ejemplo.com"  # base URL changed but verification was not reset
    with pytest.raises(IntegrityError):
        await db.flush()


async def test_verified_needs_a_verified_host(db: AsyncSession) -> None:
    project = await make_project(db)
    project.verification_status = "verified"
    project.verification_method = "dns"
    project.verified_at = NOW
    # verified_host left NULL: `NULL = host` is NULL and would slip through a naive CHECK.
    with pytest.raises(IntegrityError):
        await db.flush()


# ---------------------------------------------------------------- RN-02 (ADR-013)


async def test_rows_cannot_reference_another_project(db: AsyncSession) -> None:
    mine = await make_project(db, "Mío")
    other = await make_project(db, "Ajeno")
    foreign_identity = bearer(other)
    foreign_operation = operation(other)
    db.add_all([foreign_identity, foreign_operation])
    await db.flush()

    resource = Resource(
        project_id=mine.id,
        identity_id=foreign_identity.id,
        resource_type="pedido",
        value="101",
        source="manual",
    )
    assert await rejected(db, resource)

    my_run = run(mine)
    db.add(my_run)
    await db.flush()
    result = Result(
        project_id=mine.id,
        run_id=my_run.id,
        module="authentication",
        operation_id=foreign_operation.id,
        identity_id=foreign_identity.id,
        expected="401",
        observed="200",
        verdict="fail",
    )
    assert await rejected(db, result)


# ---------------------------------------------------------------- RF-34


async def test_one_anonymous_identity_without_credential(db: AsyncSession) -> None:
    project = await make_project(db)
    db.add(anonymous(project))
    await db.flush()

    second = anonymous(project)
    second.name = "Otra anónima"
    assert await rejected(db, second)

    with_credential = anonymous(project)
    with_credential.name = "Anónima con credencial"
    with_credential.encrypted_credential = b"x"
    assert await rejected(db, with_credential)


async def test_anonymous_identity_cannot_be_deleted(db: AsyncSession) -> None:
    project = await make_project(db)
    identity = anonymous(project)
    db.add(identity)
    await db.flush()

    identity.deleted_at = NOW
    with pytest.raises(IntegrityError):
        await db.flush()


async def test_deleting_an_identity_must_erase_its_credential(db: AsyncSession) -> None:
    project = await make_project(db)
    identity = bearer(project)
    db.add(identity)
    await db.flush()

    identity.deleted_at = NOW  # credential still there (ADR-015 says erase it)
    with pytest.raises(IntegrityError):
        await db.flush()


# ---------------------------------------------------------------- RF-41, RN-08


async def test_ownership_policy_needs_owner_field_and_confirmation(db: AsyncSession) -> None:
    project = await make_project(db)

    no_field = operation(project, "/a/{}")
    no_field.policy, no_field.confirmed_at = "owner_only", NOW
    assert await rejected(db, no_field)

    unconfirmed = operation(project, "/b/{}")
    unconfirmed.policy = "authenticated"
    assert await rejected(db, unconfirmed)

    ok = operation(project, "/c/{}")
    ok.policy, ok.owner_field, ok.confirmed_at = "owner_only", "user_id", NOW
    assert not await rejected(db, ok)


# ---------------------------------------------------------------- RF-68, RF-70


async def _finding_graph(db: AsyncSession) -> tuple[Project, Identity, Run, FindingMetric]:
    project = await make_project(db)
    identity = anonymous(project)
    finished = run(project, status="completed", end_reason="normal", finished_at=NOW)
    metric = FindingMetric(
        week=date(2026, 11, 2), module="configuration", owasp_category="API8", severity="low"
    )
    db.add_all([identity, finished, metric])
    await db.flush()
    return project, identity, finished, metric


def finding(project: Project, identity: Identity, the_run: Run, metric: FindingMetric) -> Finding:
    return Finding(
        project_id=project.id,
        module="configuration",
        finding_type="configuration.missing_header.hsts",
        operation_id=None,  # API-wide finding
        identity_id=identity.id,
        severity="low",
        owasp_category="API8",
        title="Falta HSTS",
        recommendation="Envía Strict-Transport-Security.",
        status="new",
        first_run_id=the_run.id,
        last_run_id=the_run.id,
        metric_id=metric.id,
    )


async def test_fingerprint_is_unique_even_with_null_operation(db: AsyncSession) -> None:
    project, identity, the_run, metric = await _finding_graph(db)
    db.add(finding(project, identity, the_run, metric))
    await db.flush()

    assert await rejected(db, finding(project, identity, the_run, metric))


async def test_accepted_risk_requires_reason_and_justification(db: AsyncSession) -> None:
    project, identity, the_run, metric = await _finding_graph(db)

    no_justification = finding(project, identity, the_run, metric)
    no_justification.status, no_justification.dismissal_reason = "accepted_risk", "false_positive"
    assert await rejected(db, no_justification)

    blank = finding(project, identity, the_run, metric)
    blank.status, blank.dismissal_reason, blank.justification = (
        "accepted_risk",
        "accepted_risk",
        " ",
    )
    assert await rejected(db, blank)


# ---------------------------------------------------------------- RF-14, RF-88


async def test_deleting_the_user_deletes_everything_but_metrics(db: AsyncSession) -> None:
    project, identity, the_run, metric = await _finding_graph(db)
    contract = ContractVersion(
        project_id=project.id,
        number=1,
        source="file",
        format="yaml",
        openapi_version="3.1.0",
        document=b"openapi: 3.1.0",
        sha256="0" * 64,
        operation_count=0,
    )
    the_finding = finding(project, identity, the_run, metric)
    db.add_all([contract, the_finding])
    await db.flush()
    db.add_all(
        [
            FindingOccurrence(
                finding_id=the_finding.id,
                run_id=the_run.id,
                project_id=project.id,
                severity="low",
                explanation="Falta la cabecera.",
                evidence={"status": 200},
            ),
            FindingEvent(
                project_id=project.id,
                finding_id=the_finding.id,
                to_status="new",
                reason="detected",
                run_id=the_run.id,
            ),
        ]
    )
    await db.flush()

    await db.execute(delete(User).where(User.id == project.owner_id))

    for model in (
        Project,
        Identity,
        Run,
        Finding,
        FindingOccurrence,
        FindingEvent,
        ContractVersion,
    ):
        count = await db.scalar(select(func.count()).select_from(model))
        assert count == 0, model.__tablename__
    assert await db.get(FindingMetric, metric.id) is not None  # anonymous metrics survive
