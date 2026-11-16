"""Queries on runs. With the `hindama_api` role, Row-Level Security limits every query to the
caller's projects (ADR-013); the explicit `project_id` filters keep a run inside its project."""

from collections.abc import Collection, Sequence
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import CreatedResource, FindingOccurrence, Project, Run
from hindama.models.enums import CreatedResourceStatus, RunStatus, Severity


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
