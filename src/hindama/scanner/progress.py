"""Tells the API's streams that a run moved (RF-51, RNF-03, ADR-006).

At most one `progress` per `INTERVAL_SECONDS`, so a fast run does not send one message per request.
A change inside the interval is not lost: it goes out when the interval ends. A new module goes out
at once; `end` is published by `execution` once the final state is saved.
"""

import asyncio
from uuid import UUID

from hindama.core.run_events import RunEvent, RunEvents

# RNF-03 allows 2 s from the scanner to the analyst's screen.
INTERVAL_SECONDS = 1.0


class Progress:
    def __init__(self, events: RunEvents, run_id: UUID) -> None:
        self._events = events
        self._run_id = run_id
        self._loop = asyncio.get_running_loop()
        self._last = float("-inf")
        self._pending: asyncio.Task[None] | None = None

    async def changed(self) -> None:
        """Something the stream shows changed: publish now or when the interval ends."""
        if self._pending is not None:
            return  # the publication already scheduled will read this change too
        wait = self._last + INTERVAL_SECONDS - self._loop.time()
        if wait <= 0:
            await self._publish()
        else:
            self._pending = asyncio.create_task(self._later(wait))

    async def now(self) -> None:
        """A new module: the analyst sees it at once."""
        self._cancel_pending()
        await self._publish()

    async def close(self) -> None:
        """The run stopped: `end` replaces whatever was still to be published."""
        self._cancel_pending()

    async def _later(self, wait: float) -> None:
        await asyncio.sleep(wait)
        self._pending = None
        await self._publish()

    async def _publish(self) -> None:
        self._last = self._loop.time()
        await self._events.publish(self._run_id, RunEvent.PROGRESS)

    def _cancel_pending(self) -> None:
        if self._pending is not None:
            self._pending.cancel()
            self._pending = None
