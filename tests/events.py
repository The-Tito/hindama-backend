"""Test double of the progress events (ADR-006): the API tests never need Redis."""

import asyncio
import contextlib
from collections.abc import AsyncIterator
from uuid import UUID

from hindama.core.run_events import EventsUnavailableError, RunEvent, Subscription


class _Subscription:
    def __init__(self) -> None:
        self.inbox: asyncio.Queue[RunEvent] = asyncio.Queue()

    async def receive(self, within: float) -> RunEvent | None:
        try:
            async with asyncio.timeout(max(within, 0.0)):
                return await self.inbox.get()
        except TimeoutError:
            return None


class MemoryRunEvents:
    def __init__(self) -> None:
        self.published: list[tuple[UUID, RunEvent]] = []
        self.subscribers: dict[UUID, list[_Subscription]] = {}
        self.subscribed = asyncio.Event()  # set on every new subscription

    def of(self, run_id: UUID) -> list[RunEvent]:
        return [event for published, event in self.published if published == run_id]

    async def publish(self, run_id: UUID, event: RunEvent) -> None:
        self.published.append((run_id, event))
        for subscription in self.subscribers.get(run_id, []):
            subscription.inbox.put_nowait(event)

    @contextlib.asynccontextmanager
    async def subscribe(self, run_id: UUID) -> AsyncIterator[Subscription]:
        subscription = _Subscription()
        listeners = self.subscribers.setdefault(run_id, [])
        listeners.append(subscription)
        self.subscribed.set()
        try:
            yield subscription
        finally:
            listeners.remove(subscription)

    def listening(self, run_id: UUID) -> int:
        return len(self.subscribers.get(run_id, []))

    async def close(self) -> None:
        return None


class DownRunEvents(MemoryRunEvents):
    """Redis down: subscribing fails, publishing is lost."""

    @contextlib.asynccontextmanager
    async def subscribe(self, run_id: UUID) -> AsyncIterator[Subscription]:
        raise EventsUnavailableError("ConnectionError")
        yield  # pragma: no cover - makes this an async generator
