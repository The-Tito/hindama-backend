"""Test doubles of the run queue: the API tests never need Redis."""

from uuid import UUID

from hindama.core.run_queue import QueueUnavailableError, job_key


class MemoryRunQueue:
    def __init__(self) -> None:
        self.enqueued: list[UUID] = []
        self.aborted: list[UUID] = []

    async def enqueue(self, run_id: UUID) -> str:
        self.enqueued.append(run_id)
        return job_key(run_id)

    async def abort(self, run_id: UUID) -> None:
        self.aborted.append(run_id)

    async def close(self) -> None:
        return None


class FailingRunQueue:
    """Redis down: nothing is enqueued."""

    async def enqueue(self, run_id: UUID) -> str:
        raise QueueUnavailableError("ConnectionError")

    async def abort(self, run_id: UUID) -> None:
        raise QueueUnavailableError("ConnectionError")

    async def close(self) -> None:
        return None
