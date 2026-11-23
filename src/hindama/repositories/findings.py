"""Queries on findings (CU-15; RF-65, RF-66, RF-72). With the `hindama_api` role, Row-Level
Security limits every query to the caller's projects (ADR-013); the explicit `project_id` filters
keep a finding inside its project."""

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import ColumnElement, Select, and_, case, exists, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from hindama.models import Finding, FindingEvent, FindingOccurrence, Identity, Operation, Run
from hindama.models.enums import (
    OPEN_FINDING_STATUSES,
    FindingEventReason,
    FindingStatus,
    Module,
    ResolutionReason,
    Severity,
)


@dataclass(frozen=True, slots=True)
class FindingRow:
    finding: Finding
    operation: Operation | None  # None in API-wide findings
    identity: Identity
    first_run_number: int
    last_run_number: int
    last_detected_at: datetime


@dataclass(frozen=True, slots=True)
class OccurrenceRow:
    occurrence: FindingOccurrence
    run_number: int


@dataclass(frozen=True, slots=True)
class EventRow:
    event: FindingEvent
    run_number: int | None  # None when the analyst caused it


# RF-65: from critical to info.
_SEVERITY_ORDER = case(
    {severity.value: index for index, severity in enumerate(Severity)}, value=Finding.severity
)


# The runs of a finding and the occurrence of its last run: the last detection (the scanner writes
# the finding and that occurrence in the same transaction, modelo.md section 6).
_FIRST_RUN, _LAST_RUN = aliased(Run), aliased(Run)
_LAST_OCCURRENCE = aliased(FindingOccurrence)
_LAST_DETECTED_AT = _LAST_OCCURRENCE.detected_at


def _select() -> Select[Finding, Operation, Identity, int, int, datetime]:
    """A finding with its operation, identity, run numbers and last detection."""
    project = Finding.project_id
    return (
        select(Finding, Operation, Identity, _FIRST_RUN.number, _LAST_RUN.number, _LAST_DETECTED_AT)
        .join(Identity, and_(Identity.project_id == project, Identity.id == Finding.identity_id))
        .outerjoin(
            Operation, and_(Operation.project_id == project, Operation.id == Finding.operation_id)
        )
        .join(
            _FIRST_RUN,
            and_(_FIRST_RUN.project_id == project, _FIRST_RUN.id == Finding.first_run_id),
        )
        .join(_LAST_RUN, and_(_LAST_RUN.project_id == project, _LAST_RUN.id == Finding.last_run_id))
        .join(
            _LAST_OCCURRENCE,
            and_(
                _LAST_OCCURRENCE.finding_id == Finding.id,
                _LAST_OCCURRENCE.run_id == Finding.last_run_id,
            ),
        )
    )


async def page(
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
    """RF-65. Severity first, then the most recent detection; the id breaks ties so that pages
    never overlap."""
    conditions = [Finding.project_id == project_id]
    if modules:
        conditions.append(Finding.module.in_(modules))
    if severities:
        conditions.append(Finding.severity.in_(severities))
    if statuses:
        conditions.append(Finding.status.in_(statuses))
    if identity_id is not None:
        conditions.append(Finding.identity_id == identity_id)
    if operation_id is not None:
        conditions.append(Finding.operation_id == operation_id)
    if run_id is not None:
        conditions.append(
            exists().where(
                FindingOccurrence.finding_id == Finding.id, FindingOccurrence.run_id == run_id
            )
        )
    total = await session.scalar(select(func.count()).select_from(Finding).where(*conditions))
    rows = await session.execute(
        _select()
        .where(*conditions)
        .order_by(_SEVERITY_ORDER, _LAST_DETECTED_AT.desc(), Finding.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return [FindingRow(*values) for values in rows], int(total or 0)


async def get(session: AsyncSession, project_id: UUID, finding_id: UUID) -> FindingRow | None:
    row = (
        await session.execute(
            _select().where(Finding.project_id == project_id, Finding.id == finding_id)
        )
    ).first()
    return None if row is None else FindingRow(*row)


async def lock(session: AsyncSession, project_id: UUID, finding_id: UUID) -> Finding | None:
    """Serializes the analyst's change with the scanner, which locks the finding the same way
    before it records a detection (scanner/recorder.py)."""
    finding: Finding | None = await session.scalar(
        select(Finding)
        .where(Finding.project_id == project_id, Finding.id == finding_id)
        .with_for_update()
    )
    return finding


async def occurrence(
    session: AsyncSession, project_id: UUID, finding_id: UUID, run_id: UUID
) -> OccurrenceRow | None:
    row = (
        await session.execute(
            select(FindingOccurrence, Run.number)
            .join(
                Run,
                and_(
                    Run.project_id == FindingOccurrence.project_id,
                    Run.id == FindingOccurrence.run_id,
                ),
            )
            .where(
                FindingOccurrence.project_id == project_id,
                FindingOccurrence.finding_id == finding_id,
                FindingOccurrence.run_id == run_id,
            )
        )
    ).first()
    return None if row is None else OccurrenceRow(*row)


async def occurrences(
    session: AsyncSession, project_id: UUID, finding_id: UUID, *, page: int, page_size: int
) -> tuple[list[OccurrenceRow], int]:
    """One per run that detected the finding, the most recent run first (RF-72)."""
    conditions = [
        FindingOccurrence.project_id == project_id,
        FindingOccurrence.finding_id == finding_id,
    ]
    total = await session.scalar(
        select(func.count()).select_from(FindingOccurrence).where(*conditions)
    )
    rows = await session.execute(
        select(FindingOccurrence, Run.number)
        .join(
            Run,
            and_(
                Run.project_id == FindingOccurrence.project_id, Run.id == FindingOccurrence.run_id
            ),
        )
        .where(*conditions)
        .order_by(Run.number.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return [OccurrenceRow(*values) for values in rows], int(total or 0)


async def history(session: AsyncSession, project_id: UUID, finding_id: UUID) -> list[EventRow]:
    """RF-72. Insert-only, so the identity column orders the events as they happened."""
    rows = await session.execute(
        select(FindingEvent, Run.number)
        .outerjoin(
            Run, and_(Run.project_id == FindingEvent.project_id, Run.id == FindingEvent.run_id)
        )
        .where(FindingEvent.project_id == project_id, FindingEvent.finding_id == finding_id)
        .order_by(FindingEvent.id)
    )
    return [EventRow(*values) for values in rows]


async def close_open(
    session: AsyncSession,
    project_id: UUID,
    condition: ColumnElement[bool],
    reason: ResolutionReason,
    user_id: UUID,
) -> int:
    """Administrative closure (RF-69, modelo.md 7.1): the open findings that match `condition` go
    to `resolved` with `reason`, each with its history event caused by the analyst. Not a fix, so
    it does not count in `days_to_resolve` (modelo.md 7.3)."""
    rows = (
        await session.execute(
            select(Finding.id, Finding.status)
            .where(
                Finding.project_id == project_id,
                Finding.status.in_(OPEN_FINDING_STATUSES),
                condition,
            )
            .with_for_update()
        )
    ).all()
    if not rows:
        return 0
    await session.execute(
        update(Finding)
        .where(Finding.project_id == project_id, Finding.id.in_([row.id for row in rows]))
        .values(status=FindingStatus.RESOLVED, resolution_reason=reason, resolved_at=func.now())
    )
    await session.execute(
        insert(FindingEvent),
        [
            {
                "project_id": project_id,
                "finding_id": row.id,
                "from_status": row.status,
                "to_status": FindingStatus.RESOLVED,
                "reason": FindingEventReason(reason.value),
                "user_id": user_id,
            }
            for row in rows
        ],
    )
    return len(rows)
