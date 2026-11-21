"""Requests per user to the platform's own API (RNF-09, convenciones.md section 7).

A fixed window of one minute per user, counted in Redis: `INCR` on `rate:{sub}:{minute}`, which
expires on its own. Over the limit, the API answers 429 `rate_limit.exceeded` with `Retry-After`
until the window ends.

If Redis does not answer, the request goes through and a warning is logged: the limit protects
the platform from abuse, and losing it for a moment is better than losing the whole API.
"""

import asyncio
import math
import time
from collections.abc import Callable
from typing import Protocol

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

log = structlog.get_logger(__name__)

WINDOW_SECONDS = 60
REDIS_TIMEOUT_SECONDS = 0.25
_REDIS_ERRORS = (RedisError, OSError, TimeoutError)

Clock = Callable[[], float]


class RateLimiter(Protocol):
    async def hit(self, user: str) -> int | None:
        """Counts a request of `user`. `None` if it may go on; otherwise, seconds to wait."""
        ...

    async def close(self) -> None: ...


def _retry_after(now: float) -> int:
    return max(1, math.ceil(WINDOW_SECONDS - now % WINDOW_SECONDS))


class NoRateLimiter:
    """Without Redis (development and most tests), nothing is limited."""

    async def hit(self, user: str) -> int | None:
        return None

    async def close(self) -> None:
        return None


class RedisRateLimiter:
    def __init__(self, redis: Redis, limit: int, clock: Clock = time.time) -> None:
        self.redis = redis
        self.limit = limit
        self.clock = clock

    @classmethod
    def from_url(cls, url: str, limit: int) -> "RedisRateLimiter":
        return cls(Redis.from_url(url), limit)

    async def hit(self, user: str) -> int | None:
        now = self.clock()
        key = f"rate:{user}:{int(now // WINDOW_SECONDS)}"
        try:
            async with asyncio.timeout(REDIS_TIMEOUT_SECONDS):
                async with self.redis.pipeline(transaction=True) as pipe:
                    pipe.incr(key)
                    pipe.expire(key, WINDOW_SECONDS * 2)
                    count, _ = await pipe.execute()
        except _REDIS_ERRORS as error:
            # Only the type: the message may include the Redis host.
            log.warning("rate_limit_unavailable", error=type(error).__name__)
            return None
        return None if int(count) <= self.limit else _retry_after(now)

    async def close(self) -> None:
        await self.redis.aclose()


class MemoryRateLimiter:
    """The same window in memory, for tests that need to move the clock."""

    def __init__(self, limit: int, clock: Clock = time.time) -> None:
        self.limit = limit
        self.clock = clock
        self.counts: dict[tuple[str, int], int] = {}

    async def hit(self, user: str) -> int | None:
        now = self.clock()
        key = (user, int(now // WINDOW_SECONDS))
        self.counts[key] = self.counts.get(key, 0) + 1
        return None if self.counts[key] <= self.limit else _retry_after(now)

    async def close(self) -> None:
        return None
