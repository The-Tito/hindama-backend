"""Runs left behind by a server failure (CU-23, RNF-18, RN-07; architecture 4.3).

When the scanner starts and every 5 minutes (scanner/worker.py):

- **`running` whose heartbeat expired** (no beat for `HEARTBEAT_EXPIRY_SECONDS`, measured by the
  database clock) end `failed` / `heartbeat_expired`. Their partial results stay. Their job is
  aborted in case a scanner still holds it, and `end` closes their streams.
- **`queued` whose job is no longer in Redis** (the queue was lost) are enqueued again if they are
  younger than `REQUEUE_WINDOW_SECONDS`; older ones end `failed` / `lost_in_queue`. A project is
  never blocked by a run nobody will execute (RN-07).

Once a day, `purge_audit_log()` deletes the audit log older than 6 months (RF-90, modelo.md 7.4).

Every run is taken with `FOR UPDATE SKIP LOCKED`: two scanners never reconcile the same run, and a
run that a scanner is claiming right now is left for the next pass. A run the API has not committed
yet is not visible, so it is never taken for lost.

Pending: the cleanup of created resources (RN-06, CU-23 E1) arrives with the first module that
creates them (API3). No module does today.
"""

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass, field
from uuid import UUID

import structlog
from sqlalchemy import ColumnElement, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hindama.core.run_events import RunEvent, RunEvents
from hindama.core.run_queue import QueueUnavailableError, RunQueue
from hindama.models import Run
from hindama.models.enums import EndReason, RunStatus

log = structlog.get_logger(__name__)

# The scanner beats every 10 s and SAQ gives a job up after 30 s without one; twice that leaves
# room for a slow database without failing a live run.
HEARTBEAT_EXPIRY_SECONDS = 60
REQUEUE_WINDOW_SECONDS = 10 * 60


@dataclass(slots=True)
class Reconciliation:
    expired: list[UUID] = field(default_factory=list)
    requeued: list[UUID] = field(default_factory=list)
    lost: list[UUID] = field(default_factory=list)


async def reconcile(
    session_factory: async_sessionmaker[AsyncSession], queue: RunQueue, events: RunEvents
) -> Reconciliation:
    result = Reconciliation()
    result.expired = await _expired(session_factory, queue, events)
    try:
        result.requeued, result.lost = await _queued(session_factory, queue, events)
    except QueueUnavailableError as error:
        # Without Redis nobody can tell a lost job from a waiting one: the next pass decides.
        log.warning("reconciliation_queue_unavailable", error=str(error))
    if result.expired or result.requeued or result.lost:
        log.info(
            "runs_reconciled",
            expired=len(result.expired),
            requeued=len(result.requeued),
            lost=len(result.lost),
        )
    return result


def _ago(seconds: int) -> ColumnElement[dt.datetime]:
    return func.now() - dt.timedelta(seconds=seconds)


async def _expired(
    session_factory: async_sessionmaker[AsyncSession], queue: RunQueue, events: RunEvents
) -> list[UUID]:
    async with session_factory() as session, session.begin():
        runs = (
            await session.scalars(
                select(Run)
                .where(
                    Run.status == RunStatus.RUNNING,
                    # The claim always sets a beat; the fallbacks are only a safety net.
                    func.coalesce(Run.heartbeat_at, Run.started_at, Run.created_at)
                    < _ago(HEARTBEAT_EXPIRY_SECONDS),
                )
                .with_for_update(skip_locked=True)
            )
        ).all()
        for run in runs:
            _fail(run, EndReason.HEARTBEAT_EXPIRED)
    for run in runs:
        try:
            # A scanner that is alive but stopped beating must not keep writing.
            await queue.abort(run.id)
        except QueueUnavailableError as error:
            log.warning("run_queue_unavailable", run_id=str(run.id), error=str(error))
        await _ended(events, run, EndReason.HEARTBEAT_EXPIRED)
    return [run.id for run in runs]


async def _queued(
    session_factory: async_sessionmaker[AsyncSession], queue: RunQueue, events: RunEvents
) -> tuple[list[UUID], list[UUID]]:
    requeued: list[Run] = []
    lost: list[Run] = []
    async with session_factory() as session, session.begin():
        recent = Run.created_at >= _ago(REQUEUE_WINDOW_SECONDS)
        rows: Sequence[tuple[Run, bool]] = (
            await session.execute(
                select(Run, recent)
                .where(Run.status == RunStatus.QUEUED)
                .order_by(Run.created_at)
                .with_for_update(of=Run, skip_locked=True)
            )
        ).all()
        for run, is_recent in rows:
            if await queue.has_job(run.id):
                continue
            if is_recent:
                run.job_id = await queue.enqueue(run.id)
                requeued.append(run)
            else:
                _fail(run, EndReason.LOST_IN_QUEUE)
                lost.append(run)
    for run in requeued:
        log.info("run_requeued", project_id=str(run.project_id), run_id=str(run.id))
    for run in lost:
        await _ended(events, run, EndReason.LOST_IN_QUEUE)
    return [run.id for run in requeued], [run.id for run in lost]


def _fail(run: Run, reason: EndReason) -> None:
    run.status = RunStatus.FAILED
    run.end_reason = reason
    run.finished_at = func.now()
    run.current_module = None


async def _ended(events: RunEvents, run: Run, reason: EndReason) -> None:
    await events.publish(run.id, RunEvent.END)  # after the commit: the stream reads it final
    # RF-81 (bitácora) is pending: until then, the log keeps the event.
    log.warning(
        "run_failed_by_reconciliation",
        project_id=str(run.project_id),
        run_id=str(run.id),
        end_reason=reason.value,
    )


async def purge_audit_log(session_factory: async_sessionmaker[AsyncSession]) -> int:
    """RF-90: the function belongs to `hindama_migrations`; the scanner may only execute it."""
    async with session_factory() as session, session.begin():
        deleted = await session.scalar(text("SELECT purge_audit_log()"))
    log.info("audit_log_purged", deleted=int(deleted or 0))
    return int(deleted or 0)
