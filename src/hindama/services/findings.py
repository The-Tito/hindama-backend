"""Findings: list, detail and occurrences (CU-15), and the analyst's dismissal (CU-16; RF-65,
RF-66, RF-70, RF-72, RN-02, RN-09).

The scanner creates findings and moves them between runs (modelo.md section 6); the analyst only
accepts a risk, marks a false positive, or reverts it. Both lock the finding first, so a dismissal
never interleaves with a detection. A project, finding or filter of another analyst is not found,
never forbidden (RN-02).
"""

from collections.abc import Collection
from dataclasses import dataclass
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.auth import CurrentUser
from hindama.core.errors import ConflictError, NotFoundError
from hindama.models import Finding, FindingEvent
from hindama.models.enums import (
    OPEN_FINDING_STATUSES,
    DismissalReason,
    FindingEventReason,
    FindingStatus,
    Module,
    Severity,
)
from hindama.repositories import findings as repository
from hindama.repositories import projects as projects_repository
from hindama.repositories.findings import EventRow, FindingRow, OccurrenceRow

log = structlog.get_logger(__name__)

# The event of each dismissal reason (modelo.md section 3.4).
_DISMISSAL_EVENTS = {
    DismissalReason.ACCEPTED_RISK: FindingEventReason.ACCEPTED,
    DismissalReason.FALSE_POSITIVE: FindingEventReason.FALSE_POSITIVE,
}


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


async def _locked(session: AsyncSession, project_id: UUID, finding_id: UUID) -> Finding:
    finding = await repository.lock(session, project_id, finding_id)
    if finding is None:
        raise NotFoundError()
    return finding


def _analyst_event(
    finding: Finding,
    previous: FindingStatus,
    reason: FindingEventReason,
    user: CurrentUser,
    justification: str | None = None,
) -> FindingEvent:
    """RF-72: caused by the analyst, so `user_id` and no run."""
    return FindingEvent(
        project_id=finding.project_id,
        finding_id=finding.id,
        from_status=previous,
        to_status=finding.status,
        reason=reason,
        user_id=user.id,
        justification=justification,
    )


async def dismiss(
    session: AsyncSession,
    project_id: UUID,
    finding_id: UUID,
    user: CurrentUser,
    *,
    reason: DismissalReason,
    justification: str,
) -> FindingView:
    """RF-70, RN-09. Only an open finding; a detected-again accepted one stays accepted (ADR-014).
    The router audits it (RN-09) in the same transaction."""
    finding = await _locked(session, project_id, finding_id)
    previous = FindingStatus(finding.status)
    if previous not in OPEN_FINDING_STATUSES:
        raise ConflictError(
            "finding.not_open",
            "El hallazgo no está abierto",
            "Solo se acepta el riesgo de un hallazgo nuevo, persistente o en regresión.",
        )
    finding.status = FindingStatus.ACCEPTED_RISK
    finding.dismissal_reason = reason
    finding.justification = justification
    session.add(_analyst_event(finding, previous, _DISMISSAL_EVENTS[reason], user, justification))
    await session.flush()
    log.info("finding_dismissed", finding_id=str(finding_id), reason=reason.value)
    return await get_finding(session, project_id, finding_id)


async def revert_dismissal(
    session: AsyncSession, project_id: UUID, finding_id: UUID, user: CurrentUser
) -> None:
    """RF-70. Back to persistent whatever it was before: it is open again, and the next run that
    evaluates it and does not find it resolves it."""
    finding = await _locked(session, project_id, finding_id)
    if finding.status != FindingStatus.ACCEPTED_RISK:
        raise ConflictError(
            "finding.not_dismissed",
            "El hallazgo no está aceptado",
            "Solo se revierte un hallazgo con el riesgo aceptado o marcado como falso positivo.",
        )
    finding.status = FindingStatus.PERSISTENT
    finding.dismissal_reason = None
    finding.justification = None
    session.add(
        _analyst_event(finding, FindingStatus.ACCEPTED_RISK, FindingEventReason.REVERTED, user)
    )
    await session.flush()
    log.info("finding_dismissal_reverted", finding_id=str(finding_id))
