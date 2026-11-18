"""Progress of a run without database nor Redis: how often the scanner publishes (RNF-03) and what
the stream sends (RF-51, ADR-006). The stream reads `FakeRun`s instead of the database."""

import asyncio
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from typing import cast

import pytest
from pydantic import BaseModel

from hindama.api import run_stream
from hindama.api.run_stream import first_event_id, stream
from hindama.core.run_events import RunEvent
from hindama.models.enums import RunStatus
from hindama.scanner import progress as progress_module
from hindama.scanner.progress import Progress
from hindama.schemas.runs import Run
from hindama.services.runs import RunView
from tests.events import DownRunEvents, MemoryRunEvents

RUN_ID = uuid.uuid4()

# ------------------------------------------------------------------ the scanner publishes


@pytest.fixture
def interval(monkeypatch: pytest.MonkeyPatch) -> float:
    monkeypatch.setattr(progress_module, "INTERVAL_SECONDS", 0.05)
    return 0.05


async def test_the_first_change_is_published_at_once(interval: float) -> None:
    events = MemoryRunEvents()
    progress = Progress(events, RUN_ID)

    await progress.changed()

    assert events.of(RUN_ID) == [RunEvent.PROGRESS]


async def test_a_burst_is_published_once_more_when_the_interval_ends(interval: float) -> None:
    events = MemoryRunEvents()
    progress = Progress(events, RUN_ID)

    for _ in range(20):
        await progress.changed()
    assert events.of(RUN_ID) == [RunEvent.PROGRESS]  # not one per cell
    await asyncio.sleep(interval * 2)

    assert events.of(RUN_ID) == [RunEvent.PROGRESS] * 2  # the last change is not lost


async def test_a_new_module_is_published_at_once(interval: float) -> None:
    events = MemoryRunEvents()
    progress = Progress(events, RUN_ID)
    await progress.changed()
    await progress.changed()  # scheduled

    await progress.now()
    await asyncio.sleep(interval * 2)

    assert events.of(RUN_ID) == [RunEvent.PROGRESS] * 2  # the scheduled one was replaced


async def test_nothing_is_published_after_closing(interval: float) -> None:
    events = MemoryRunEvents()
    progress = Progress(events, RUN_ID)
    await progress.changed()
    await progress.changed()

    await progress.close()
    await asyncio.sleep(interval * 2)

    assert events.of(RUN_ID) == [RunEvent.PROGRESS]


# ------------------------------------------------------------------ the stream


class FakeProgress(BaseModel):
    status: RunStatus
    cells_evaluated: int


class FakeRun(BaseModel):
    status: RunStatus
    progress: FakeProgress


def run(status: RunStatus, cells: int = 0) -> FakeRun:
    return FakeRun(status=status, progress=FakeProgress(status=status, cells_evaluated=cells))


class Database:
    """What `load` reads: the test changes `current`."""

    def __init__(self, current: FakeRun | None) -> None:
        self.current = current
        self.reads = 0

    async def load(self) -> RunView | None:
        self.reads += 1
        return cast(RunView | None, self.current)


def render(view: RunView) -> Run:
    return cast(Run, view)


def open_stream(events: MemoryRunEvents, db: Database, first_id: int = 1) -> AsyncGenerator[str]:
    return stream(events, RUN_ID, db.load, render, first_id)


async def read_all(chunks: AsyncIterator[str]) -> list[str]:
    return [chunk async for chunk in chunks]


def names(chunks: list[str]) -> list[str]:
    """`retry`, the event names and `ping`, in order."""
    result = []
    for chunk in chunks:
        if chunk.startswith("retry:"):
            result.append("retry")
        elif chunk.startswith(": ping"):
            result.append("ping")
        else:
            result.append(chunk.split("event: ")[1].split("\n")[0])
    return result


@pytest.fixture(autouse=True)
def short_times(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_stream, "PING_SECONDS", 0.2)
    monkeypatch.setattr(run_stream, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(run_stream, "MAX_STREAM_SECONDS", 5.0)


@pytest.mark.parametrize(
    ("header", "expected"),
    [("", 1), ("7", 8), ("abc", 1), ("-3", 1), ("1" * 40, 1), ("٣", 1)],
)
def test_event_ids_continue_after_the_last_one(header: str, expected: int) -> None:
    assert first_event_id(header) == expected


async def test_a_finished_run_sends_snapshot_and_end() -> None:
    events = MemoryRunEvents()

    chunks = await read_all(open_stream(events, Database(run(RunStatus.COMPLETED, 3))))

    assert names(chunks) == ["retry", "snapshot", "end"]
    assert chunks[0] == "retry: 3000\n\n"
    assert chunks[1] == (
        'id: 1\nevent: snapshot\ndata: {"status":"completed",'
        '"progress":{"status":"completed","cells_evaluated":3}}\n\n'
    )
    assert chunks[2].startswith("id: 2\nevent: end\n")
    assert events.listening(RUN_ID) == 0


async def test_snapshot_then_progress_then_end() -> None:
    events = MemoryRunEvents()
    db = Database(run(RunStatus.RUNNING, 0))
    reading = asyncio.create_task(read_all(open_stream(events, db, first_id=5)))
    await events.subscribed.wait()
    await asyncio.sleep(0.01)

    db.current = run(RunStatus.RUNNING, 1)
    await events.publish(RUN_ID, RunEvent.PROGRESS)
    await asyncio.sleep(0.01)
    await events.publish(RUN_ID, RunEvent.PROGRESS)  # nothing changed: nothing is sent
    await asyncio.sleep(0.01)
    db.current = run(RunStatus.CANCELLED, 1)
    await events.publish(RUN_ID, RunEvent.END)
    chunks = await asyncio.wait_for(reading, timeout=2)

    assert names(chunks) == ["retry", "snapshot", "progress", "end"]
    assert [chunk.split("\n")[0] for chunk in chunks[1:]] == ["id: 5", "id: 6", "id: 7"]
    assert '"cells_evaluated":1' in chunks[2]
    assert events.listening(RUN_ID) == 0


async def test_it_subscribes_before_reading_the_snapshot() -> None:
    events = MemoryRunEvents()
    db = Database(run(RunStatus.RUNNING))
    chunks = open_stream(events, db)

    await anext(chunks)  # retry
    assert (events.listening(RUN_ID), db.reads) == (0, 0)
    await anext(chunks)  # snapshot
    assert (events.listening(RUN_ID), db.reads) == (1, 1)
    await chunks.aclose()  # the browser left
    assert events.listening(RUN_ID) == 0


async def test_an_idle_stream_pings() -> None:
    events = MemoryRunEvents()
    db = Database(run(RunStatus.RUNNING))
    chunks = open_stream(events, db)
    await anext(chunks)
    await anext(chunks)

    assert await asyncio.wait_for(anext(chunks), timeout=1) == ": ping\n\n"
    await chunks.aclose()


async def test_a_lost_end_is_found_at_the_next_reading() -> None:
    db = Database(run(RunStatus.RUNNING))
    chunks = open_stream(MemoryRunEvents(), db)
    await anext(chunks)
    await anext(chunks)

    db.current = run(RunStatus.FAILED)  # the scanner died before publishing

    assert "event: end" in await asyncio.wait_for(anext(chunks), timeout=1)


async def test_without_redis_it_reads_the_database_every_second() -> None:
    db = Database(run(RunStatus.RUNNING))
    reading = asyncio.create_task(read_all(open_stream(DownRunEvents(), db)))
    await asyncio.sleep(0.05)

    db.current = run(RunStatus.RUNNING, 2)
    await asyncio.sleep(0.05)
    db.current = run(RunStatus.COMPLETED, 2)
    chunks = await asyncio.wait_for(reading, timeout=2)

    assert names(chunks) == ["retry", "snapshot", "progress", "end"]


async def test_a_deleted_run_closes_the_stream() -> None:
    db = Database(run(RunStatus.RUNNING))
    chunks = open_stream(MemoryRunEvents(), db)
    await anext(chunks)
    await anext(chunks)

    db.current = None

    assert await read_all(chunks) == []


async def test_the_stream_closes_after_its_maximum_life(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_stream, "MAX_STREAM_SECONDS", 0.05)
    events = MemoryRunEvents()

    chunks = await asyncio.wait_for(
        read_all(open_stream(events, Database(run(RunStatus.RUNNING)))), timeout=1
    )

    assert names(chunks) == ["retry", "snapshot"]  # the browser reconnects (CU-13 A1)
    assert events.listening(RUN_ID) == 0
