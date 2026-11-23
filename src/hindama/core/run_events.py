"""Progress events of a run (ADR-006): the scanner publishes, the API's stream listens.

The channel `run:{id}` carries only the kind of event, never data: on each one the stream reads
the run again from PostgreSQL, with the caller's Row-Level Security (ADR-013). So nothing of the
analyst's project passes through Redis (as with the queue, ADR-012), the payload of `progress`
and `end` is built in one place, and a lost message only delays the next reading.
"""

import asyncio
import contextlib
from collections.abc import AsyncIterator
from enum import StrEnum
from typing import Protocol
from uuid import UUID

import structlog
from redis.asyncio import Redis
from redis.asyncio.client import PubSub
from redis.exceptions import RedisError

log = structlog.get_logger(__name__)

# Publishing never holds a run back: a slow Redis loses a message, not time.
PUBLISH_TIMEOUT_SECONDS = 2.0


class RunEvent(StrEnum):
    PROGRESS = "progress"
    END = "end"


class EventsUnavailableError(Exception):
    """Redis did not accept the subscription; the stream falls back to reading the database."""


def channel(run_id: UUID) -> str:
    return f"run:{run_id}"


class Subscription(Protocol):
    async def receive(self, within: float) -> RunEvent | None:
        """The next event, or `None` if none arrived within `within` seconds."""
        ...


class RunEvents(Protocol):
    async def publish(self, run_id: UUID, event: RunEvent) -> None:
        """Best effort: never raises."""
        ...

    def subscribe(self, run_id: UUID) -> contextlib.AbstractAsyncContextManager[Subscription]:
        """Raises `EventsUnavailableError` on entering if Redis does not answer."""
        ...

    async def close(self) -> None: ...


_REDIS_ERRORS = (RedisError, OSError, TimeoutError)


class _RedisSubscription:
    def __init__(self, pubsub: PubSub) -> None:
        self._pubsub = pubsub

    async def receive(self, within: float) -> RunEvent | None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(within, 0.0)
        while True:
            try:
                # Returns None at once when what it read was the subscription's confirmation:
                # keep waiting until the deadline.
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=max(deadline - loop.time(), 0.0)
                )
            except _REDIS_ERRORS as error:
                raise EventsUnavailableError(type(error).__name__) from error
            if message is not None:
                break
            if loop.time() >= deadline:
                return None
        try:
            return RunEvent(message["data"].decode())
        except (AttributeError, ValueError):
            return RunEvent.PROGRESS  # unknown: reading the run again is always safe


class RedisRunEvents:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    @classmethod
    def from_url(cls, url: str) -> "RedisRunEvents":
        return cls(Redis.from_url(url))

    async def publish(self, run_id: UUID, event: RunEvent) -> None:
        try:
            async with asyncio.timeout(PUBLISH_TIMEOUT_SECONDS):
                await self.redis.publish(channel(run_id), event.value)
        except _REDIS_ERRORS as error:
            # Only the type: the message may include the Redis host.
            log.warning("run_event_not_published", run_id=str(run_id), error=type(error).__name__)

    @contextlib.asynccontextmanager
    async def subscribe(self, run_id: UUID) -> AsyncIterator[Subscription]:
        pubsub = self.redis.pubsub()
        try:
            await pubsub.subscribe(channel(run_id))
        except _REDIS_ERRORS as error:
            await _close(pubsub)
            raise EventsUnavailableError(type(error).__name__) from error
        try:
            yield _RedisSubscription(pubsub)
        finally:
            await _close(pubsub)

    async def close(self) -> None:
        with contextlib.suppress(*_REDIS_ERRORS):
            await self.redis.aclose()


async def _close(pubsub: PubSub) -> None:
    with contextlib.suppress(*_REDIS_ERRORS):
        await pubsub.aclose()  # type: ignore[no-untyped-call]


class UnconfiguredRunEvents:
    """Without `HINDAMA_REDIS_URL`: nothing is published and the stream reads the database."""

    async def publish(self, run_id: UUID, event: RunEvent) -> None:
        return None

    @contextlib.asynccontextmanager
    async def subscribe(self, run_id: UUID) -> AsyncIterator[Subscription]:
        raise EventsUnavailableError("redis_url is not set")
        yield  # pragma: no cover - makes this an async generator

    async def close(self) -> None:
        return None
