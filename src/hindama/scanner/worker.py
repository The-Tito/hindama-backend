"""The SAQ worker of the scanner (ADR-012, PT-02).

- `concurrency` runs per process, each one as its own asyncio task.
- The job is touched every few seconds while the run lives; the sweep (every 10 s) aborts a job
  whose worker stopped touching it, so a dead scanner is noticed in seconds, not minutes.
- `cancellation_hard_deadline_s` leaves time for the cleanup of created resources (RN-06).
"""

from uuid import UUID

from saq import Queue, Worker
from saq.types import Context, PartialTimersDict
from sqlalchemy.ext.asyncio import AsyncEngine

from hindama.core.destinations import SystemResolver
from hindama.core.ownership import NetworkOwnershipChecker, SystemTxtResolver
from hindama.core.run_queue import EXECUTE_RUN, QUEUE_NAME
from hindama.core.safe_http import SafeHttpClient
from hindama.db.session import create_session_factory, engine_for
from hindama.scanner.config import ScannerSettings
from hindama.scanner.execution import Scanner, execute
from hindama.scanner.requester import SCAN_LIMITS

SWEEP_SECONDS = 10
CANCELLATION_DEADLINE_SECONDS = 30.0


class ScannerContext(Context, total=False):
    scanner: Scanner
    engine: AsyncEngine


async def execute_run(ctx: ScannerContext, *, run_id: str) -> None:
    job = ctx["job"]
    await execute(ctx["scanner"], UUID(run_id), touch=job.update)


execute_run.__qualname__ = EXECUTE_RUN  # the name the API enqueues


def build_worker(
    settings: ScannerSettings, queue: Queue | None = None, scanner: Scanner | None = None
) -> Worker[ScannerContext]:
    """`queue` and `scanner` are injected only by tests."""
    queue = queue or Queue.from_url(settings.redis_url.get_secret_value(), name=QUEUE_NAME)

    async def startup(ctx: ScannerContext) -> None:
        if scanner is not None:
            ctx["scanner"] = scanner
            return
        engine = engine_for(settings.database_url.get_secret_value(), settings.database_pool_size)
        resolver = SystemResolver()
        own_addresses = settings.own_ip_addresses

        def http_client(host: str) -> SafeHttpClient:
            return SafeHttpClient(
                host, resolver=resolver, own_addresses=own_addresses, limits=SCAN_LIMITS
            )

        ctx["engine"] = engine
        ctx["scanner"] = Scanner(
            session_factory=create_session_factory(engine),
            ownership_checker=NetworkOwnershipChecker(
                resolver=resolver,
                txt_resolver=SystemTxtResolver(),
                own_addresses=own_addresses,
            ),
            cipher=settings.credential_cipher(),
            http_client=http_client,
        )

    async def shutdown(ctx: ScannerContext) -> None:
        engine = ctx.get("engine")
        if engine is not None:
            await engine.dispose()

    return Worker(
        queue,
        functions=[execute_run],
        concurrency=settings.concurrency,
        startup=startup,
        shutdown=shutdown,
        # SAQ's defaults, except the sweep (60 s by default): a dead worker is seen in ~10 s.
        timers=PartialTimersDict(schedule=1, worker_info=10, sweep=SWEEP_SECONDS, abort=1),
        cancellation_hard_deadline_s=CANCELLATION_DEADLINE_SECONDS,
    )
