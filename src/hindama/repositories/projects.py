"""`projects` and the facts the list and the dashboard compute from other tables (RF-12, RF-15).

Every query runs as `hindama_api` with Row-Level Security: only the caller's projects (and their
children) are visible, so a foreign id behaves exactly like a missing one (RN-02, ADR-013).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import ScalarSelect, Select, SQLColumnExpression, and_, delete, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from hindama.models import ContractVersion, Finding, Identity, Operation, Project, Resource, Run
from hindama.models.enums import (
    ACTIVE_RUN_STATUSES,
    OPEN_FINDING_STATUSES,
    OWNERSHIP_POLICIES,
    AuthType,
    IdentityRole,
    Policy,
    RunStatus,
    Severity,
)

ANONYMOUS_IDENTITY_NAME = "Anónimo"

Sort = Literal["created_at", "-created_at", "name", "-name", "last_run_at", "-last_run_at"]


def _last_run_at() -> ScalarSelect[datetime]:
    """When the latest run finished, or started, or was queued."""
    return (
        select(func.coalesce(Run.finished_at, Run.started_at, Run.created_at))
        .where(Run.project_id == Project.id)
        .order_by(Run.number.desc())
        .limit(1)
        .correlate(Project)
        .scalar_subquery()
    )


def _open_findings() -> ScalarSelect[int]:
    return (
        select(func.count())
        .select_from(Finding)
        .where(Finding.project_id == Project.id, Finding.status.in_(OPEN_FINDING_STATUSES))
        .correlate(Project)
        .scalar_subquery()
    )


def _has_completed_run() -> ColumnElement[bool]:
    return exists().where(Run.project_id == Project.id, Run.status == RunStatus.COMPLETED)


@dataclass(frozen=True, slots=True)
class ProjectRow:
    project: Project
    last_run_at: datetime | None
    open_findings: int
    concluded: bool  # RN-10: a completed run and no open finding (modelo.md 4.4)


def _rows() -> Select[Project, datetime | None, int, bool]:
    open_findings = _open_findings()
    return select(
        Project,
        _last_run_at().label("last_run_at"),
        open_findings.label("open_findings"),
        and_(_has_completed_run(), open_findings == 0).label("concluded"),
    )


async def list_page(
    session: AsyncSession, sort: Sort, page: int, page_size: int
) -> tuple[list[ProjectRow], int]:
    total = await session.scalar(select(func.count()).select_from(Project)) or 0
    column = sort.removeprefix("-")
    descending = sort.startswith("-")
    key: SQLColumnExpression[Any] = {
        "created_at": Project.created_at,
        "name": func.lower(Project.name),
        "last_run_at": _last_run_at(),
    }[column]
    order = key.desc().nulls_last() if descending else key.asc().nulls_last()
    statement = (
        _rows()
        .order_by(order, Project.id.desc() if descending else Project.id.asc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    result = await session.execute(statement)
    rows = [
        ProjectRow(p, last_run_at, int(count), bool(done)) for p, last_run_at, count, done in result
    ]
    return rows, total


async def get_row(session: AsyncSession, project_id: UUID) -> ProjectRow | None:
    result = (await session.execute(_rows().where(Project.id == project_id))).one_or_none()
    if result is None:
        return None
    project, last_run_at, count, done = result
    return ProjectRow(project, last_run_at, int(count), bool(done))


async def get(session: AsyncSession, project_id: UUID) -> Project | None:
    return await session.get(Project, project_id)


async def create(
    session: AsyncSession,
    *,
    owner_id: UUID,
    name: str,
    description: str | None,
    base_url: str,
    host: str,
    verification_code: str,
) -> Project:
    """The project and its anonymous identity (RF-34), in the caller's transaction."""
    project = Project(
        owner_id=owner_id,
        name=name,
        description=description,
        base_url=base_url,
        host=host,
        verification_code=verification_code,
    )
    session.add(project)
    await session.flush()
    session.add(
        Identity(
            project_id=project.id,
            name=ANONYMOUS_IDENTITY_NAME,
            role=IdentityRole.OTHER,
            auth_type=AuthType.NONE,
        )
    )
    await session.flush()
    await session.refresh(project)
    return project


async def delete_project(session: AsyncSession, project_id: UUID) -> None:
    """Cascades to everything the project contains (RF-14)."""
    await session.execute(delete(Project).where(Project.id == project_id))


async def has_active_run(session: AsyncSession, project_id: UUID) -> bool:
    statement = select(
        exists().where(Run.project_id == project_id, Run.status.in_(ACTIVE_RUN_STATUSES))
    )
    return bool(await session.scalar(statement))


async def current_contract(session: AsyncSession, project_id: UUID) -> ContractVersion | None:
    statement = (
        select(ContractVersion)
        .where(ContractVersion.project_id == project_id)
        .order_by(ContractVersion.number.desc())
        .limit(1)
    )
    return await session.scalar(statement)


async def last_run(session: AsyncSession, project_id: UUID) -> Run | None:
    statement = select(Run).where(Run.project_id == project_id).order_by(Run.number.desc()).limit(1)
    return await session.scalar(statement)


async def open_findings_by_severity(session: AsyncSession, project_id: UUID) -> dict[Severity, int]:
    statement = (
        select(Finding.severity, func.count())
        .where(Finding.project_id == project_id, Finding.status.in_(OPEN_FINDING_STATUSES))
        .group_by(Finding.severity)
    )
    counts = {
        Severity(severity): int(count) for severity, count in await session.execute(statement)
    }
    return {severity: counts.get(severity, 0) for severity in Severity}


@dataclass(frozen=True, slots=True)
class Configuration:
    """What the modules need (RF-45), counted over live rows only."""

    authenticated_identities: int  # not anonymous, not deleted
    has_admin_identity: bool
    identities_with_resources: int
    has_ownership_policy: bool  # a confirmed owner_only/owner_or_admin on a current operation
    has_admin_only_policy: bool


async def configuration(session: AsyncSession, project_id: UUID) -> Configuration:
    live_identity = and_(
        Identity.project_id == project_id,
        Identity.auth_type != AuthType.NONE,
        Identity.deleted_at.is_(None),
    )
    current_operation = and_(Operation.project_id == project_id, Operation.retired_at.is_(None))
    statement = select(
        select(func.count()).select_from(Identity).where(live_identity).scalar_subquery(),
        exists().where(live_identity, Identity.role == IdentityRole.ADMIN),
        select(func.count(func.distinct(Resource.identity_id)))
        .join(Identity, and_(Identity.id == Resource.identity_id, live_identity))
        .where(Resource.project_id == project_id)
        .scalar_subquery(),
        exists().where(current_operation, Operation.policy.in_(OWNERSHIP_POLICIES)),
        exists().where(current_operation, Operation.policy == Policy.ADMIN_ONLY),
    )
    identities, admin, with_resources, ownership, admin_only = (
        await session.execute(statement)
    ).one()
    return Configuration(
        authenticated_identities=int(identities),
        has_admin_identity=bool(admin),
        identities_with_resources=int(with_resources),
        has_ownership_policy=bool(ownership),
        has_admin_only_policy=bool(admin_only),
    )
