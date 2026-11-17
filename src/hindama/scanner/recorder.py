"""Writes what a run evaluates (ADR-014, modelo.md section 6, RF-51, RF-62).

One short transaction per finished cell: its `results` row, its finding if it failed, and the
progress counters. A cell cut short (cancellation, limit) writes nothing, so it resolves nothing.

Findings are matched by fingerprint `(module, finding_type, operation, identity)` as soon as they
are detected, not when the run ends: progress shows them live (RF-51), and a scanner that dies
keeps what it found. A fingerprint is evaluated once per run, so the outcome is the same. Resolving
the open findings that were not detected again runs at the end (task 4.2).
"""

import datetime as dt
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hindama.models import Finding, FindingEvent, FindingMetric, FindingOccurrence, Result, Run
from hindama.models.enums import FindingEventReason, FindingStatus, Module, Severity, Verdict

OPEN = (FindingStatus.NEW, FindingStatus.PERSISTENT, FindingStatus.REGRESSION)


@dataclass(frozen=True, slots=True)
class Detection:
    finding_type: str  # a stable code of the module's catalog (RNF-24)
    severity: Severity
    owasp_category: str
    cwe: str | None
    title: str
    recommendation: str
    explanation: str
    evidence: dict[str, Any]  # already masked and truncated (evidence.Masker)


@dataclass(frozen=True, slots=True)
class CellOutcome:
    module: Module
    operation_id: UUID | None
    identity_id: UUID
    expected: str
    observed: str
    verdict: Verdict
    detection: Detection | None = None


def _monday(today: dt.date) -> dt.date:
    """RF-89: metrics keep the week, never the exact date."""
    return today - dt.timedelta(days=today.weekday())


class Recorder:
    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], run_id: UUID, project_id: UUID
    ) -> None:
        self._sessions = session_factory
        self.run_id = run_id
        self.project_id = project_id

    async def plan(self, cells: int) -> None:
        await self._update_run(cells_planned=cells)

    async def start(self, module: Module) -> None:
        await self._update_run(current_module=module)

    async def sent(self, requests: int) -> None:
        await self._update_run(requests_sent=func.greatest(Run.requests_sent, requests))

    async def record(self, outcome: CellOutcome, requests: int) -> None:
        async with self._sessions() as session, session.begin():
            session.add(
                Result(
                    project_id=self.project_id,
                    run_id=self.run_id,
                    module=outcome.module,
                    operation_id=outcome.operation_id,
                    identity_id=outcome.identity_id,
                    expected=outcome.expected,
                    observed=outcome.observed,
                    verdict=outcome.verdict,
                )
            )
            if outcome.detection is not None:
                await self._detected(session, outcome, outcome.detection)
            await session.execute(
                update(Run)
                .where(Run.id == self.run_id)
                .values(
                    cells_evaluated=Run.cells_evaluated + 1,
                    requests_sent=func.greatest(Run.requests_sent, requests),
                )
            )

    async def _detected(
        self, session: AsyncSession, outcome: CellOutcome, detection: Detection
    ) -> None:
        finding = await session.scalar(
            select(Finding)
            .where(
                Finding.project_id == self.project_id,
                Finding.module == outcome.module,
                Finding.finding_type == detection.finding_type,
                Finding.operation_id.is_not_distinct_from(outcome.operation_id),
                Finding.identity_id == outcome.identity_id,
            )
            .with_for_update()
        )
        if finding is None:
            finding = await self._new(session, outcome, detection)
            await self._event(session, finding, None, FindingEventReason.DETECTED)
        else:
            previous = FindingStatus(finding.status)
            finding.last_run_id = self.run_id
            if previous in OPEN:
                finding.status = FindingStatus.PERSISTENT
                if previous != FindingStatus.PERSISTENT:
                    await self._event(session, finding, previous, FindingEventReason.DETECTED)
            elif previous == FindingStatus.RESOLVED:
                finding.status = FindingStatus.REGRESSION
                finding.resolution_reason = None
                finding.resolved_at = None
                await session.execute(
                    update(FindingMetric)
                    .where(FindingMetric.id == finding.metric_id)
                    .values(regressions=FindingMetric.regressions + 1)
                )
                await self._event(session, finding, previous, FindingEventReason.REGRESSION)
            # accepted_risk stays as the analyst left it (ADR-014)
        session.add(
            FindingOccurrence(
                finding_id=finding.id,
                run_id=self.run_id,
                project_id=self.project_id,
                severity=detection.severity,
                explanation=detection.explanation,
                evidence=detection.evidence,
            )
        )

    async def _new(
        self, session: AsyncSession, outcome: CellOutcome, detection: Detection
    ) -> Finding:
        metric = FindingMetric(
            week=_monday(dt.datetime.now(dt.UTC).date()),
            module=outcome.module,
            owasp_category=detection.owasp_category,
            cwe=detection.cwe,
            severity=detection.severity,
        )
        session.add(metric)
        await session.flush()
        finding = Finding(
            project_id=self.project_id,
            module=outcome.module,
            finding_type=detection.finding_type,
            operation_id=outcome.operation_id,
            identity_id=outcome.identity_id,
            severity=detection.severity,
            owasp_category=detection.owasp_category,
            cwe=detection.cwe,
            title=detection.title,
            recommendation=detection.recommendation,
            status=FindingStatus.NEW,
            first_run_id=self.run_id,
            last_run_id=self.run_id,
            metric_id=metric.id,
        )
        session.add(finding)
        await session.flush()
        return finding

    async def _event(
        self,
        session: AsyncSession,
        finding: Finding,
        previous: FindingStatus | None,
        reason: FindingEventReason,
    ) -> None:
        session.add(
            FindingEvent(
                project_id=self.project_id,
                finding_id=finding.id,
                from_status=previous,
                to_status=finding.status,
                reason=reason,
                run_id=self.run_id,
            )
        )

    async def _update_run(self, **values: Any) -> None:
        async with self._sessions() as session, session.begin():
            await session.execute(update(Run).where(Run.id == self.run_id).values(**values))
