"""The limits of one run (RF-47): requests per second, concurrency and total requests.

Every request of a run, logins included, goes through one `RequestLimiter`, whatever module sends
it. The duration limit is enforced by `execution._run` with a timeout around the modules.
"""

import asyncio
import contextlib
from collections.abc import AsyncIterator


class BudgetExhaustedError(Exception):
    """The run reached `max_requests`: it ends with `limit_reached` (CU-12 E5)."""


class RequestLimiter:
    """Spaces requests evenly at `requests_per_second` and keeps at most `concurrency` in flight.

    Even spacing, not bursts: the analyst's API sees a steady rate it can plan for (RN-05).
    """

    def __init__(self, *, requests_per_second: int, concurrency: int, max_requests: int) -> None:
        self._interval = 1 / requests_per_second
        self._slots = asyncio.Semaphore(concurrency)
        self._max_requests = max_requests
        self._next_at = 0.0
        self.sent = 0

    @property
    def remaining(self) -> int:
        return max(self._max_requests - self.sent, 0)

    @contextlib.asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Waits for a free slot and for the request's turn; raises `BudgetExhaustedError`."""
        async with self._slots:
            if self.sent >= self._max_requests:
                raise BudgetExhaustedError()
            self.sent += 1
            loop = asyncio.get_running_loop()
            now = loop.time()
            turn = max(now, self._next_at)
            self._next_at = turn + self._interval
            if turn > now:
                await asyncio.sleep(turn - now)
            yield
