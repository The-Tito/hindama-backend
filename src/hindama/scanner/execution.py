"""The life of one run in the scanner (CU-12 steps 6 to 10, architecture 4.3).

    queued --claim--> running --verify (RF-20)--> modules --finish--> completed | cancelled | failed

Independent of SAQ: the worker calls `execute` with a `touch` that keeps the job alive. Every step
opens its own short transaction, so the progress and the heartbeat are visible while it runs.

Pending in later tasks: the modules (3.2), cancellation by the analyst and progress events (3.3),
and the reconciliation of runs left behind by a dead scanner (3.4, CU-23).
"""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hindama.core.ownership import Outcome, OwnershipChecker, published_code
from hindama.core.run_queue import HEARTBEAT_INTERVAL_SECONDS
from hindama.models import Project, Run
from hindama.models.enums import EndReason, RunStatus, VerificationMethod, VerificationStatus

log = structlog.get_logger(__name__)

# The API enqueues before its transaction commits (services/runs.py): the row may take a moment
# to become visible. A run that never appears was rolled back and has nothing to execute.
VISIBILITY_WAIT_SECONDS = 5.0
VISIBILITY_POLL_SECONDS = 0.1

# The code is no longer where it was, or the host now points somewhere forbidden: the ownership
# is not valid any more (RF-20, CU-12 E2). A connection error proves nothing about ownership.
_OWNERSHIP_LOST = {
    Outcome.FILE_NOT_FOUND,
    Outcome.CONTENT_MISMATCH,
    Outcome.TXT_MISSING,
    Outcome.DESTINATION_NOT_ALLOWED,
}

SECONDS_PER_MINUTE = 60  # the tests shorten it

Touch = Callable[[], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class Scanner:
    """What every run needs, shared by the runs of one process."""

    session_factory: async_sessionmaker[AsyncSession]
    ownership_checker: OwnershipChecker


@dataclass(frozen=True, slots=True)
class Ending:
    status: RunStatus
    end_reason: EndReason


async def execute(scanner: Scanner, run_id: UUID, touch: Touch) -> None:
    run = await _claim(scanner, run_id)
    if run is None:
        return
    log.info("run_started", project_id=str(run.project_id), run_id=str(run_id))
    heartbeat = asyncio.create_task(_beat(scanner, run_id, touch))
    try:
        ending = await _run(scanner, run)
    except Exception as error:  # one run failing never takes the process down (ADR-012)
        # Only the type: a message could carry data of the analyst's API.
        log.error("run_error", run_id=str(run_id), error=type(error).__name__)
        ending = Ending(RunStatus.FAILED, EndReason.ERROR)
    finally:
        heartbeat.cancel()
    await _finish(scanner, run_id, ending)
    log.info(
        "run_finished",
        project_id=str(run.project_id),
        run_id=str(run_id),
        status=ending.status.value,
        end_reason=ending.end_reason.value,
    )


async def _claim(scanner: Scanner, run_id: UUID) -> Run | None:
    """Moves the run from `queued` to `running`, once its row is visible."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + VISIBILITY_WAIT_SECONDS
    while True:
        async with scanner.session_factory() as session, session.begin():
            run = await session.scalar(select(Run).where(Run.id == run_id).with_for_update())
            if run is not None:
                if run.status != RunStatus.QUEUED:
                    log.warning("run_not_queued", run_id=str(run_id), status=run.status)
                    return None
                run.status = RunStatus.RUNNING
                run.started_at = func.now()
                run.heartbeat_at = func.now()
                await session.flush()
                await session.refresh(run)
                return run
        if loop.time() >= deadline:
            log.warning("run_not_found", run_id=str(run_id))
            return None
        await asyncio.sleep(VISIBILITY_POLL_SECONDS)


async def _beat(scanner: Scanner, run_id: UUID, touch: Touch) -> None:
    """Keeps the job alive in SAQ and the run alive for the reconciliation (CU-23)."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
        await touch()
        async with scanner.session_factory() as session, session.begin():
            await session.execute(
                update(Run).where(Run.id == run_id).values(heartbeat_at=func.now())
            )


async def _run(scanner: Scanner, run: Run) -> Ending:
    if not await _still_verified(scanner, run.project_id):
        return Ending(RunStatus.CANCELLED, EndReason.VERIFICATION_INVALID)
    limit_seconds = run.config["limits"]["max_duration_minutes"] * SECONDS_PER_MINUTE
    try:
        async with asyncio.timeout(limit_seconds):  # RF-47; the job timeout is only a net
            await _modules(scanner, run)
    except TimeoutError:
        return Ending(RunStatus.COMPLETED, EndReason.LIMIT_REACHED)
    return Ending(RunStatus.COMPLETED, EndReason.NORMAL)


async def _still_verified(scanner: Scanner, project_id: UUID) -> bool:
    """RF-20: before sending anything, the code must still be published on the host."""
    async with scanner.session_factory() as session:
        project = await session.get(Project, project_id)
    if (
        project is None
        or project.verification_status != VerificationStatus.VERIFIED
        or project.verified_host != project.host
        or project.verification_method is None
    ):
        return False
    method = VerificationMethod(project.verification_method)
    result = await scanner.ownership_checker.check(
        method,
        base_url=project.base_url,
        host=project.host,
        code=published_code(project.verification_code),
    )
    if result.outcome == Outcome.VERIFIED:
        return True
    if result.outcome not in _OWNERSHIP_LOST:
        raise OwnershipCheckError(result.outcome.value)
    async with scanner.session_factory() as session, session.begin():
        await session.execute(
            update(Project)
            .where(Project.id == project_id)
            .values(
                verification_status=VerificationStatus.PENDING,
                verification_method=None,
                verified_host=None,
                verified_at=None,
            )
        )
    # RF-81 (bitácora) is pending: until then, the log keeps the event.
    log.info(
        "project_verification_lost",
        project_id=str(project_id),
        method=method.value,
        outcome=result.outcome.value,
    )
    return False


class OwnershipCheckError(Exception):
    """The check could not reach the host: the run fails, the verification stays."""


async def _modules(scanner: Scanner, run: Run) -> None:
    """The modules arrive in task 3.2. Until then a run plans no cells and ends at once."""
    async with scanner.session_factory() as session, session.begin():
        await session.execute(update(Run).where(Run.id == run.id).values(cells_planned=0))


async def _finish(scanner: Scanner, run_id: UUID, ending: Ending) -> None:
    async with scanner.session_factory() as session, session.begin():
        await session.execute(
            update(Run)
            .where(Run.id == run_id, Run.status == RunStatus.RUNNING)
            .values(
                status=ending.status,
                end_reason=ending.end_reason,
                finished_at=func.now(),
                current_module=None,
            )
        )
