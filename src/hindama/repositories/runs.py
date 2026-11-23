"""Queries on runs. With the `hindama_api` role, Row-Level Security limits every query to the
caller's projects (ADR-013); the explicit `project_id` filters keep a run inside its project."""

from collections.abc import Collection, Sequence
from uuid import UUID

from sqlalchemy import Select, and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import (
    CreatedResource,
    FindingOccurrence,
    Identity,
    Operation,
    Project,
    Result,
    Run,
)
from hindama.models.enums import CreatedResourceStatus, Module, RunStatus, Severity, Verdict


async def lock_project(session: AsyncSession, project_id: UUID) -> Project | None:
    """Serializes the launches of one project: the number and the one-active rule stay exact."""
    project: Project | None = await session.scalar(
        select(Project).where(Project.id == project_id).with_for_update()
    )
    return project


async def next_number(session: AsyncSession, project_id: UUID) -> int:
    highest = await session.scalar(select(func.max(Run.number)).where(Run.project_id == project_id))
    return (highest or 0) + 1


async def get(session: AsyncSession, project_id: UUID, run_id: UUID) -> Run | None:
    run: Run | None = await session.scalar(
        select(Run).where(Run.project_id == project_id, Run.id == run_id)
    )
    return run


async def lock(session: AsyncSession, project_id: UUID, run_id: UUID) -> Run | None:
    """Serializes a cancellation with the scanner, which reads the request under the same lock."""
    run: Run | None = await session.scalar(
        select(Run).where(Run.project_id == project_id, Run.id == run_id).with_for_update()
    )
    return run


def _filtered(project_id: UUID, statuses: Collection[RunStatus]) -> Select[Run]:
    statement = select(Run).where(Run.project_id == project_id)
    if statuses:
        statement = statement.where(Run.status.in_(statuses))
    return statement


async def page(
    session: AsyncSession,
    project_id: UUID,
    statuses: Collection[RunStatus],
    page: int,
    page_size: int,
) -> tuple[Sequence[Run], int]:
    """Most recent first (RF-63)."""
    statement = _filtered(project_id, statuses)
    total = await session.scalar(select(func.count()).select_from(statement.subquery()))
    rows = await session.scalars(
        statement.order_by(Run.number.desc()).offset((page - 1) * page_size).limit(page_size)
    )
    return rows.all(), int(total or 0)


async def findings_by_severity(
    session: AsyncSession, run_ids: Collection[UUID]
) -> dict[UUID, dict[Severity, int]]:
    """Failures detected in each run (RF-63): its occurrences, by the severity they had then."""
    result = {run_id: dict.fromkeys(Severity, 0) for run_id in run_ids}
    if not run_ids:
        return result
    statement = (
        select(FindingOccurrence.run_id, FindingOccurrence.severity, func.count())
        .where(FindingOccurrence.run_id.in_(run_ids))
        .group_by(FindingOccurrence.run_id, FindingOccurrence.severity)
    )
    for run_id, severity, count in await session.execute(statement):
        result[run_id][Severity(severity)] = int(count)
    return result


async def created_resources(
    session: AsyncSession, run_id: UUID
) -> dict[CreatedResourceStatus, int]:
    statement = (
        select(CreatedResource.status, func.count())
        .where(CreatedResource.run_id == run_id)
        .group_by(CreatedResource.status)
    )
    rows = await session.execute(statement)
    counts = {CreatedResourceStatus(status): int(count) for status, count in rows}
    return {status: counts.get(status, 0) for status in CreatedResourceStatus}


# A cell of the matrix with its operation (None in API-wide checks) and identity.
type Cell = tuple[Result, Operation | None, Identity]

# The catalog order of the modules (the enum's), for the matrix (RF-64).
_MODULE_ORDER = case(
    {module.value: index for index, module in enumerate(Module)}, value=Result.module
)


async def results(
    session: AsyncSession,
    project_id: UUID,
    run_id: UUID,
    *,
    modules: Collection[Module],
    verdicts: Collection[Verdict],
    identity_id: UUID | None,
    operation_id: UUID | None,
    page: int,
    page_size: int,
) -> tuple[list[Cell], int]:
    """The evaluated cells of a run (RF-64), with their operation and identity. Order: module in
    catalog order, the API-wide checks first, then path, method and identity name; the identity
    and the row id break ties so that pages never overlap."""
    conditions = [Result.project_id == project_id, Result.run_id == run_id]
    if modules:
        conditions.append(Result.module.in_(modules))
    if verdicts:
        conditions.append(Result.verdict.in_(verdicts))
    if identity_id is not None:
        conditions.append(Result.identity_id == identity_id)
    if operation_id is not None:
        conditions.append(Result.operation_id == operation_id)
    total = await session.scalar(select(func.count()).select_from(Result).where(*conditions))
    statement = (
        select(Result, Operation, Identity)
        .join(
            Identity,
            and_(Identity.project_id == Result.project_id, Identity.id == Result.identity_id),
        )
        .outerjoin(
            Operation,
            and_(Operation.project_id == Result.project_id, Operation.id == Result.operation_id),
        )
        .where(*conditions)
        .order_by(
            _MODULE_ORDER,
            Operation.path.nulls_first(),
            Operation.method,
            Identity.name,
            Identity.id,
            Result.id,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = await session.execute(statement)
    return [(result, operation, identity) for result, operation, identity in rows], int(total or 0)
