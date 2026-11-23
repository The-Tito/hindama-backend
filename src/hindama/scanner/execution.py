"""The life of one run in the scanner (CU-12 steps 6 to 10, architecture 4.3).

    queued --claim--> running --verify (RF-20)--> modules --finish--> completed | cancelled | failed

Independent of SAQ: the worker calls `execute` with a `touch` that keeps the job alive. Every step
opens its own short transaction, so the progress and the heartbeat are visible while it runs.

The modules (`scanner/modules`) share one `RequestLimiter` (RF-47) and one `SafeHttpClient` bound
to the verified host (RF-50). Modules that are not implemented yet plan no cells.

Progress and cancellation (task 3.3, ADR-006, RF-51, RF-52):

- The `Recorder` tells the API's streams when the run moves (`scanner/progress.py`); `end` is
  published once the final state is saved.
- The API cancels by aborting the SAQ job, which cancels this task within about a second, including
  the request in flight. The final state is written in a shielded task, so a second cancellation
  cannot leave it half written. Only a run with `cancel_requested_at` ends `cancelled_by_user`:
  any other cancellation (the worker stopping) leaves the run to the reconciliation
  (`scanner/reconciliation.py`, CU-23).
- The results of the cells already evaluated stay (RF-52). No module creates resources yet, so
  there is nothing to clean up (RN-06); the cleanup arrives with the first module that writes.
"""

import asyncio
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hindama.core.audit import BlockCollector, HostHasher, collect_blocks
from hindama.core.credentials import CredentialCipher
from hindama.core.ownership import Outcome, OwnershipChecker, published_code
from hindama.core.run_events import RunEvent, RunEvents
from hindama.core.run_queue import HEARTBEAT_INTERVAL_SECONDS
from hindama.core.safe_http import SafeHttpClient
from hindama.models import Project, Run
from hindama.models.enums import (
    AuditAction,
    AuthType,
    BlockStage,
    DailyMetricName,
    EndReason,
    Module,
    RunStatus,
    VerificationMethod,
    VerificationStatus,
)
from hindama.repositories import audit as audit_log
from hindama.repositories import metrics
from hindama.repositories.audit import NewEntry
from hindama.scanner import context as run_context
from hindama.scanner.evidence import Masker
from hindama.scanner.limiter import BudgetExhaustedError, RequestLimiter
from hindama.scanner.modules import Cell, Scan, ScanModule
from hindama.scanner.modules.authentication import Authentication
from hindama.scanner.modules.configuration import Configuration
from hindama.scanner.modules.function_access import FunctionAccess
from hindama.scanner.modules.object_access import ObjectAccess
from hindama.scanner.modules.resource_consumption import ResourceConsumption
from hindama.scanner.progress import Progress
from hindama.scanner.recorder import Recorder
from hindama.scanner.requester import Requester
from hindama.scanner.resolution import resolve_not_detected
from hindama.services import audit
from hindama.services.projects import run_modules

log = structlog.get_logger(__name__)

# The API enqueues before its transaction commits (services/runs.py): the row may take a moment
# to become visible. A run that never appears was rolled back and has nothing to execute.
VISIBILITY_WAIT_SECONDS = 5.0
VISIBILITY_POLL_SECONDS = 0.1

# The code is no longer where it was, or the host now points somewhere forbidden: the ownership
# is not valid any more (RF-20, CU-12 E2). A connection error proves nothing about ownership.
# RF-20: one DNS or HTTP hiccup must not take the verification away. A failed check is repeated
# with a short pause, and only the last answer counts. A host that really dropped the code still
# loses it, a few seconds later.
RECHECK_ATTEMPTS = 3
RECHECK_PAUSE_SECONDS = 2.0

_OWNERSHIP_LOST = {
    Outcome.FILE_NOT_FOUND,
    Outcome.CONTENT_MISMATCH,
    Outcome.TXT_MISSING,
    Outcome.DESTINATION_NOT_ALLOWED,
}

SECONDS_PER_MINUTE = 60  # the tests shorten it

Touch = Callable[[], Awaitable[None]]

# Run in the catalog order of the run (RF-44). The rest arrive with the next PRs of task 3.2.
MODULES: dict[Module, Callable[[], ScanModule]] = {
    Module.AUTHENTICATION: Authentication,
    Module.CONFIGURATION: Configuration,
    Module.OBJECT_ACCESS: ObjectAccess,
    Module.FUNCTION_ACCESS: FunctionAccess,
    Module.RESOURCE_CONSUMPTION: ResourceConsumption,
}
# Anonymous count of how runs end (RF-78); `runs_started` is counted when the API creates it.
ENDING_METRICS = {
    RunStatus.CANCELLED: DailyMetricName.RUNS_CANCELLED,
    RunStatus.FAILED: DailyMetricName.RUNS_FAILED,
}


@dataclass(frozen=True, slots=True)
class Scanner:
    """What every run needs, shared by the runs of one process."""

    session_factory: async_sessionmaker[AsyncSession]
    ownership_checker: OwnershipChecker
    cipher: CredentialCipher
    # A client bound to the project's host (ADR-008); tests allow their loopback server.
    http_client: Callable[[str], SafeHttpClient]
    events: RunEvents
    hasher: HostHasher  # the audit log keeps a host's HMAC, never the host (ADR-015)
    recheck_pause_seconds: float = RECHECK_PAUSE_SECONDS  # tests use 0: no fixed waits


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
    except asyncio.CancelledError:
        # SAQ cancelled the job: the analyst (RF-52) or the worker stopping. The cancellation
        # goes on to SAQ once the final state is saved.
        await _shielded(_stopped(scanner, run))
        raise
    except Exception as error:  # one run failing never takes the process down (ADR-012)
        # Only the type: a message could carry data of the analyst's API.
        log.error("run_error", run_id=str(run_id), error=type(error).__name__)
        ending = Ending(RunStatus.FAILED, EndReason.ERROR)
    finally:
        heartbeat.cancel()
    await _shielded(_end(scanner, run, ending))


# Tasks that must finish even if the job is cancelled again; kept here so they are not collected.
_SHIELDED: set[asyncio.Task[None]] = set()


async def _shielded(step: Coroutine[Any, Any, None]) -> None:
    task = asyncio.create_task(step)
    _SHIELDED.add(task)
    task.add_done_callback(_SHIELDED.discard)
    await asyncio.shield(task)


async def _stopped(scanner: Scanner, run: Run) -> None:
    # Under the row lock: if the API is still cancelling, wait for its commit (services/runs.py).
    async with scanner.session_factory() as session, session.begin():
        requested = await session.scalar(
            select(Run.cancel_requested_at).where(Run.id == run.id).with_for_update()
        )
    if requested is None:
        log.warning("run_interrupted", project_id=str(run.project_id), run_id=str(run.id))
        return
    await _end(scanner, run, Ending(RunStatus.CANCELLED, EndReason.CANCELLED_BY_USER))


async def _end(scanner: Scanner, run: Run, ending: Ending) -> None:
    await _finish(scanner, run, ending)
    await scanner.events.publish(run.id, RunEvent.END)
    log.info(
        "run_finished",
        project_id=str(run.project_id),
        run_id=str(run.id),
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
    """Keeps the job alive in SAQ and the run alive for the reconciliation (CU-23).

    A failed beat (Redis or the database hiccuping) is logged and the next one is tried: if one
    error ended this task, a live run would stop beating and be failed as dead.
    """
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
        try:
            await touch()
            async with scanner.session_factory() as session, session.begin():
                await session.execute(
                    update(Run).where(Run.id == run_id).values(heartbeat_at=func.now())
                )
        except Exception as error:
            # Only the type: the message may include the host of Redis or the database.
            log.warning("run_heartbeat_failed", run_id=str(run_id), error=type(error).__name__)


async def _run(scanner: Scanner, run: Run) -> Ending:
    # Every destination the SSRF guard blocks is audited (RF-81), whatever ends the run.
    with collect_blocks() as blocks:
        try:
            verified = await _still_verified(scanner, run)
        finally:
            await _audit_blocks(scanner, run, blocks, BlockStage.VERIFICATION)
    if not verified:
        return Ending(RunStatus.CANCELLED, EndReason.VERIFICATION_INVALID)
    limit_seconds = run.config["limits"]["max_duration_minutes"] * SECONDS_PER_MINUTE
    with collect_blocks() as blocks:
        try:
            async with asyncio.timeout(limit_seconds):  # RF-47; the job timeout is only a net
                await _modules(scanner, run)
        except (TimeoutError, BudgetExhaustedError):  # duration or total requests (CU-12 E5)
            return Ending(RunStatus.COMPLETED, EndReason.LIMIT_REACHED)
        finally:
            await _audit_blocks(scanner, run, blocks, BlockStage.RUN)
    return Ending(RunStatus.COMPLETED, EndReason.NORMAL)


async def _owner(scanner: Scanner, project_id: UUID) -> UUID | None:
    async with scanner.session_factory() as session:
        owner: UUID | None = await session.scalar(
            select(Project.owner_id).where(Project.id == project_id)
        )
    return owner


async def _audit_blocks(
    scanner: Scanner, run: Run, blocks: BlockCollector, stage: BlockStage
) -> None:
    """One entry per reason and host, on behalf of the project's owner (no browser IP)."""
    if not blocks.blocks:
        return
    await audit.write_blocks(
        scanner.session_factory,
        scanner.hasher,
        blocks,
        stage,
        user_id=await _owner(scanner, run.project_id),
        project_id=run.project_id,
        run_id=run.id,
    )


async def _still_verified(scanner: Scanner, run: Run) -> bool:
    """RF-20: before sending anything, the code must still be published on the host."""
    project_id = run.project_id
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
    code = published_code(project.verification_code)
    for attempt in range(1, RECHECK_ATTEMPTS + 1):
        result = await scanner.ownership_checker.check(
            method, base_url=project.base_url, host=project.host, code=code
        )
        if result.outcome == Outcome.VERIFIED or attempt == RECHECK_ATTEMPTS:
            break
        log.info(
            "ownership_recheck_failed",
            project_id=str(project_id),
            attempt=attempt,
            outcome=result.outcome.value,
        )
        await asyncio.sleep(scanner.recheck_pause_seconds)
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
        # Audited with the change itself (RF-81): both happen, or neither.
        await audit_log.add(
            session,
            NewEntry(
                AuditAction.PROJECT_VERIFICATION_LOST,
                user_id=project.owner_id,
                project_id=project_id,
                host=scanner.hasher.digest(project.host),
                details={"run_id": str(run.id), "verification_method": method.value},
            ),
        )
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
    async with scanner.session_factory() as session:
        context = await run_context.load(session, scanner.cipher, run)
    modules = [MODULES[module]() for module in run_modules(run.config) if module in MODULES]
    plans = [(module, module.plan(context)) for module in modules]
    progress = Progress(scanner.events, run.id)
    recorder = Recorder(scanner.session_factory, run.id, run.project_id, progress)
    try:
        await recorder.plan(sum(len(cells) for _, cells in plans))
        await _scan(scanner, run, context, plans, recorder)
    finally:
        await progress.close()


async def _scan(
    scanner: Scanner,
    run: Run,
    context: run_context.RunContext,
    plans: Sequence[tuple[ScanModule, Sequence[Cell]]],
    recorder: Recorder,
) -> None:
    limits = run.config["limits"]
    limiter = RequestLimiter(
        requests_per_second=limits["requests_per_second"],
        concurrency=limits["concurrency"],
        max_requests=limits["max_requests"],
    )
    masker = Masker(
        secrets=[secret for actor in context.actors for secret in actor.secrets()],
        header_names=[
            actor.field_name
            for actor in context.actors
            if actor.auth_type == AuthType.HEADER and actor.field_name
        ],
    )
    async with scanner.http_client(context.host) as client:
        requester = Requester(client, limiter, context.base_url, masker)
        scan = Scan(context, requester, recorder, scanner.session_factory)
        try:
            for module, cells in plans:
                await recorder.start(module.module)
                await _cells(module, cells, scan, limits["concurrency"])
        finally:
            await recorder.sent(limiter.sent)


async def _cells(module: ScanModule, cells: Sequence[Cell], scan: Scan, concurrency: int) -> None:
    gate = asyncio.Semaphore(concurrency)

    async def one(cell: Cell) -> None:
        async with gate:
            outcome = await module.evaluate(cell, scan)
            await scan.recorder.record(outcome, scan.requester.sent)

    try:
        async with asyncio.TaskGroup() as group:
            for cell in cells:
                group.create_task(one(cell))
    except ExceptionGroup as group:
        # The first real error fails the run with its own type; a spent budget ends it normally.
        _, rest = group.split(BudgetExhaustedError)
        if rest is not None:
            raise rest.exceptions[0] from None
        raise BudgetExhaustedError() from None


async def _finish(scanner: Scanner, run: Run, ending: Ending) -> None:
    """The final status and the findings this run no longer found (RF-68), in one transaction."""
    async with scanner.session_factory() as session, session.begin():
        ended = await session.scalar(
            update(Run)
            .where(Run.id == run.id, Run.status == RunStatus.RUNNING)
            .values(
                status=ending.status,
                end_reason=ending.end_reason,
                finished_at=func.now(),
                current_module=None,
            )
            .returning(Run.id)
        )
        # Already final (the reconciliation failed it): it resolved there, not twice.
        if ended is not None:
            ending_metric = ENDING_METRICS.get(ending.status)
            if ending_metric is not None:
                await metrics.increment_daily(session, ending_metric)
            resolved = await resolve_not_detected(session, run.project_id, run.id)
            if resolved:
                log.info("findings_resolved", run_id=str(run.id), count=resolved)
