"""Findings: list, detail and occurrences (CU-15; RF-65, RF-66, RF-72, RN-02).

The scanner creates and moves findings (modelo.md section 6); the API only reads them here. A
project, finding or filter of another analyst is not found, never forbidden (RN-02).
"""

from collections.abc import Collection
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.errors import NotFoundError
from hindama.models.enums import FindingStatus, Module, Severity
from hindama.repositories import findings as repository
from hindama.repositories import projects as projects_repository
from hindama.repositories.findings import EventRow, FindingRow, OccurrenceRow


@dataclass(frozen=True, slots=True)
class FindingView:
    row: FindingRow
    last_occurrence: OccurrenceRow
    history: list[EventRow]


async def _project(session: AsyncSession, project_id: UUID) -> None:
    if await projects_repository.get(session, project_id) is None:
        raise NotFoundError()


async def list_findings(
    session: AsyncSession,
    project_id: UUID,
    *,
    modules: Collection[Module],
    severities: Collection[Severity],
    statuses: Collection[FindingStatus],
    run_id: UUID | None,
    identity_id: UUID | None,
    operation_id: UUID | None,
    page: int,
    page_size: int,
) -> tuple[list[FindingRow], int]:
    """RF-65. A filter by a run, identity or operation of another project matches nothing."""
    await _project(session, project_id)
    return await repository.page(
        session,
        project_id,
        modules=modules,
        severities=severities,
        statuses=statuses,
        run_id=run_id,
        identity_id=identity_id,
        operation_id=operation_id,
        page=page,
        page_size=page_size,
    )


async def get_finding(session: AsyncSession, project_id: UUID, finding_id: UUID) -> FindingView:
    row = await repository.get(session, project_id, finding_id)
    if row is None:
        raise NotFoundError()
    last = await repository.occurrence(session, project_id, finding_id, row.finding.last_run_id)
    # `get` already joins this occurrence: the scanner writes both in one transaction.
    if last is None:  # pragma: no cover
        raise NotFoundError()
    return FindingView(row, last, await repository.history(session, project_id, finding_id))


async def list_occurrences(
    session: AsyncSession, project_id: UUID, finding_id: UUID, *, page: int, page_size: int
) -> tuple[list[OccurrenceRow], int]:
    if await repository.get(session, project_id, finding_id) is None:
        raise NotFoundError()
    return await repository.occurrences(
        session, project_id, finding_id, page=page, page_size=page_size
    )
