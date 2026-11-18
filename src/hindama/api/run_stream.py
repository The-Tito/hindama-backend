"""`streamRunEvents`: the progress of a run as Server-Sent Events (CU-13, RF-51, RNF-03, ADR-006).

    retry → snapshot → progress* → end        (`: ping` every 15 s without other events)

- It subscribes to `run:{id}` **before** reading the snapshot, so an event published in between is
  never lost: at worst the run is read once more.
- Every event reads the run again from PostgreSQL in its own short transaction, with the caller's
  Row-Level Security (ADR-013). The stream never holds a database connection while it waits.
- `progress` goes out only when the progress changed; `end` when the run reached a final state.
- Without Redis (or if it goes down), the stream reads the database every second: still within the
  2 s of RNF-03, only more expensive.
- It closes after `MAX_STREAM_SECONDS`; the browser reconnects and starts again with `snapshot`.
"""

import asyncio
import contextlib
import itertools
from collections.abc import AsyncGenerator, Awaitable, Callable
from uuid import UUID

import structlog
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from hindama.core.run_events import EventsUnavailableError, RunEvent, RunEvents, Subscription
from hindama.models.enums import ACTIVE_RUN_STATUSES
from hindama.schemas.runs import Run
from hindama.services.runs import RunView

log = structlog.get_logger(__name__)

PING_SECONDS = 15.0
POLL_SECONDS = 1.0
MAX_STREAM_SECONDS = 15 * 60.0
RETRY_MILLISECONDS = 3000
MAX_EVENT_ID = 10**15  # a Last-Event-ID beyond this starts over at 1

Load = Callable[[], Awaitable[RunView | None]]  # None: the run is gone (project deleted)
Render = Callable[[RunView], Run]


class EventStreamResponse(StreamingResponse):
    media_type = "text/event-stream"


# No caching, and no buffering in a proxy (Caddy, ADR-006).
STREAM_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


class _Polling:
    """Stands in for the subscription when Redis does not answer."""

    async def receive(self, within: float) -> RunEvent | None:
        await asyncio.sleep(max(min(within, POLL_SECONDS), 0.0))
        return RunEvent.PROGRESS


def first_event_id(last_event_id: str) -> int:
    """Ids keep growing across reconnections; anything unexpected starts over."""
    if last_event_id.isascii() and last_event_id.isdecimal() and int(last_event_id) < MAX_EVENT_ID:
        return int(last_event_id) + 1
    return 1


def _event(event_id: int, name: str, data: BaseModel) -> str:
    # model_dump_json writes one line: newlines inside strings are escaped.
    return f"id: {event_id}\nevent: {name}\ndata: {data.model_dump_json()}\n\n"


def _finished(run: Run) -> bool:
    return run.status not in ACTIVE_RUN_STATUSES


async def stream(
    events: RunEvents, run_id: UUID, load: Load, render: Render, first_id: int
) -> AsyncGenerator[str]:
    ids = itertools.count(first_id)
    yield f"retry: {RETRY_MILLISECONDS}\n\n"
    async with contextlib.AsyncExitStack() as stack:
        subscription: Subscription
        try:
            subscription = await stack.enter_async_context(events.subscribe(run_id))
        except EventsUnavailableError as error:
            log.warning("run_events_unavailable", run_id=str(run_id), error=str(error))
            subscription = _Polling()

        view = await load()
        if view is None:
            return
        run = render(view)
        yield _event(next(ids), "snapshot", run)
        if _finished(run):
            yield _event(next(ids), "end", run)
            return

        loop = asyncio.get_running_loop()
        closes_at = loop.time() + MAX_STREAM_SECONDS
        ping_at = loop.time() + PING_SECONDS
        shown = run.progress
        while (now := loop.time()) < closes_at:
            try:
                # Whatever arrives (or nothing, at the ping), the database has the truth.
                await subscription.receive(min(ping_at, closes_at) - now)
            except EventsUnavailableError as error:
                log.warning("run_events_unavailable", run_id=str(run_id), error=str(error))
                subscription = _Polling()
            view = await load()
            if view is None:
                return
            run = render(view)
            if _finished(run):
                yield _event(next(ids), "end", run)
                return
            if run.progress != shown:
                shown = run.progress
                ping_at = loop.time() + PING_SECONDS
                yield _event(next(ids), "progress", run.progress)
            elif loop.time() >= ping_at:
                ping_at = loop.time() + PING_SECONDS
                yield ": ping\n\n"
