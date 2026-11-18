"""Resolving what a run evaluated again and no longer found (RF-68, ADR-014; modelo.md section 6,
step 2).

An open finding becomes `resolved` (`not_detected`) only if the run has a `pass` or `fail` cell for
its same `(module, operation, identity)` and did not detect it again. What was not evaluated keeps
its status: a run of one module never resolves the findings of another, and a cell left half-done
by a cancellation has no row in `results`. The rule also holds for cancelled and failed runs, in
what they managed to evaluate.

It runs once per run, in the transaction that writes its final status, so the stream's `end`
already shows the findings resolved.
"""

from uuid import UUID

from sqlalchemy import exists, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.models import Finding, FindingEvent, FindingMetric, FindingOccurrence, Result
from hindama.models.enums import (
    OPEN_FINDING_STATUSES,
    FindingEventReason,
    FindingStatus,
    ResolutionReason,
    Verdict,
)

# Only these verdicts mean the check was evaluated (contract, `Verdict`).
EVALUATED = (Verdict.PASS, Verdict.FAIL)


async def resolve_not_detected(session: AsyncSession, project_id: UUID, run_id: UUID) -> int:
    """Step 2 of modelo.md section 6. Returns how many findings it resolved."""
    evaluated = exists().where(
        Result.run_id == run_id,
        Result.module == Finding.module,
        Result.operation_id.is_not_distinct_from(Finding.operation_id),
        Result.identity_id == Finding.identity_id,
        Result.verdict.in_(EVALUATED),
    )
    detected = exists().where(
        FindingOccurrence.finding_id == Finding.id, FindingOccurrence.run_id == run_id
    )
    # Locked like the recorder and the analyst's dismissal do (services/findings.py).
    rows = (
        await session.execute(
            select(Finding.id, Finding.status, Finding.metric_id)
            .where(
                Finding.project_id == project_id,
                Finding.status.in_(OPEN_FINDING_STATUSES),
                evaluated,
                ~detected,
            )
            .with_for_update()
        )
    ).all()
    if not rows:
        return 0
    ids = [finding_id for finding_id, _, _ in rows]
    await session.execute(
        update(Finding)
        .where(Finding.project_id == project_id, Finding.id.in_(ids))
        .values(
            status=FindingStatus.RESOLVED,
            resolution_reason=ResolutionReason.NOT_DETECTED,
            resolved_at=func.now(),
        )
    )
    await session.execute(
        insert(FindingEvent),
        [
            {
                "project_id": project_id,
                "finding_id": finding_id,
                "from_status": status,
                "to_status": FindingStatus.RESOLVED,
                "reason": FindingEventReason.NOT_DETECTED,
                "run_id": run_id,
            }
            for finding_id, status, _ in rows
        ],
    )
    # RF-78: days from the first detection, only the first time it is resolved (modelo.md 7.3).
    # Only a real fix counts: deleting an identity or retiring an operation does not.
    await session.execute(
        update(FindingMetric)
        .where(
            FindingMetric.id.in_([metric_id for _, _, metric_id in rows]),
            FindingMetric.days_to_resolve.is_(None),
        )
        .values(
            days_to_resolve=select(
                func.greatest(func.current_date() - func.date(Finding.detected_at), 0)
            )
            .where(Finding.metric_id == FindingMetric.id)
            .scalar_subquery()
        )
    )
    return len(rows)
