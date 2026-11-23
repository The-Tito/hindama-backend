"""The SAQ worker of the scanner (ADR-012, PT-02).

- `concurrency` runs per process, each one as its own asyncio task.
- The job is touched every few seconds while the run lives; the sweep (every 10 s) aborts a job
  whose worker stopped touching it, so a dead scanner is noticed in seconds, not minutes.
- `cancellation_hard_deadline_s` leaves time for the cleanup of created resources (RN-06).
- The reconciliation of runs left behind (CU-23) runs when the worker starts and every 5 minutes;
  the purge of the audit log, once a day (RF-90). SAQ's cron jobs are unique per queue: with several
  scanners, each schedule runs once.
"""

from uuid import UUID

import structlog
from saq import CronJob, Queue, Worker
from saq.types import Context, PartialTimersDict
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.core.destinations import SystemResolver
from hindama.core.ownership import NetworkOwnershipChecker, SystemTxtResolver
from hindama.core.run_events import RedisRunEvents
from hindama.core.run_queue import EXECUTE_RUN, QUEUE_NAME, SaqRunQueue
from hindama.core.safe_http import SafeHttpClient
from hindama.db.session import create_session_factory, engine_for
from hindama.scanner.config import ScannerSettings
from hindama.scanner.execution import Scanner, execute
from hindama.scanner.reconciliation import purge_audit_log, reconcile
from hindama.scanner.requester import SCAN_LIMITS

log = structlog.get_logger(__name__)

SWEEP_SECONDS = 10
RECONCILE_CRON = "*/5 * * * *"
PURGE_CRON = "17 4 * * *"  # 04:17 UTC, away from the hour marks other jobs use
CRON_TIMEOUT_SECONDS = 120
CANCELLATION_DEADLINE_SECONDS = 30.0


class ScannerContext(Context, total=False):
    scanner: Scanner
    engine: AsyncEngine
    events: RedisRunEvents
    run_queue: SaqRunQueue


async def execute_run(ctx: ScannerContext, *, run_id: str) -> None:
    job = ctx["job"]
    await execute(ctx["scanner"], UUID(run_id), touch=job.update)


execute_run.__qualname__ = EXECUTE_RUN  # the name the API enqueues


async def reconcile_runs(ctx: ScannerContext) -> None:
    scanner = ctx["scanner"]
    await reconcile(scanner.session_factory, ctx["run_queue"], scanner.events)


async def purge_audit(ctx: ScannerContext) -> None:
    await purge_audit_log(ctx["scanner"].session_factory)


def build_worker(
    settings: ScannerSettings, queue: Queue | None = None, scanner: Scanner | None = None
) -> Worker[ScannerContext]:
    """`queue` and `scanner` are injected only by tests."""
    queue = queue or Queue.from_url(settings.redis_url.get_secret_value(), name=QUEUE_NAME)

    async def startup(ctx: ScannerContext) -> None:
        ctx["run_queue"] = SaqRunQueue(queue)
        ctx["scanner"] = scanner or _scanner(ctx)
        try:
            # Runs a previous scanner left behind, before taking new ones (CU-23).
            await reconcile_runs(ctx)
        except Exception as error:  # a failed pass must not stop the scanner; the cron retries
            log.error("reconciliation_failed", error=type(error).__name__)

    def _scanner(ctx: ScannerContext) -> Scanner:
        engine = engine_for(settings.database_url.get_secret_value(), settings.database_pool_size)
        resolver = SystemResolver()
        own_addresses = settings.own_ip_addresses

        def http_client(host: str) -> SafeHttpClient:
            return SafeHttpClient(
                host, resolver=resolver, own_addresses=own_addresses, limits=SCAN_LIMITS
            )

        # Progress events go to the same Redis as the queue (ADR-006).
        events = RedisRunEvents.from_url(settings.redis_url.get_secret_value())
        ctx["engine"] = engine
        ctx["events"] = events
        return Scanner(
            session_factory=create_session_factory(engine),
            ownership_checker=NetworkOwnershipChecker(
                resolver=resolver,
                txt_resolver=SystemTxtResolver(),
                own_addresses=own_addresses,
            ),
            cipher=settings.credential_cipher(),
            http_client=http_client,
            events=events,
            hasher=settings.host_hasher(),
        )

    async def shutdown(ctx: ScannerContext) -> None:
        engine = ctx.get("engine")
        if engine is not None:
            await engine.dispose()
        events = ctx.get("events")
        if events is not None:
            await events.close()

    return Worker(
        queue,
        functions=[execute_run],
        cron_jobs=[
            CronJob(reconcile_runs, cron=RECONCILE_CRON, timeout=CRON_TIMEOUT_SECONDS),
            CronJob(purge_audit, cron=PURGE_CRON, timeout=CRON_TIMEOUT_SECONDS),
        ],
        concurrency=settings.concurrency,
        startup=startup,
        shutdown=shutdown,
        # SAQ's defaults, except the sweep (60 s by default): a dead worker is seen in ~10 s.
        timers=PartialTimersDict(schedule=1, worker_info=10, sweep=SWEEP_SECONDS, abort=1),
        cancellation_hard_deadline_s=CANCELLATION_DEADLINE_SECONDS,
    )
