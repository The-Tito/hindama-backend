"""The queue of runs (ADR-012): the API enqueues a run id; the scanner takes it.

The job carries only the run id. Everything else (modules, limits, credentials) is read by the
scanner from PostgreSQL, so nothing sensitive passes through Redis.
"""

import contextlib
from typing import Protocol
from uuid import UUID

from redis.exceptions import RedisError
from saq import Queue, Status

QUEUE_NAME = "runs"
EXECUTE_RUN = "execute_run"

# RF-47 caps a run at 30 minutes; the scanner enforces it. The job timeout is the safety net
# (architecture 4.3), with room for the cleanup of created resources (RN-06).
JOB_TIMEOUT_SECONDS = 31 * 60
# SAQ considers a job dead when it is not touched for this long; the scanner touches it every
# HEARTBEAT_INTERVAL_SECONDS (PT-02: detected in ~10 s after a SIGKILL with a short sweep).
JOB_HEARTBEAT_SECONDS = 30
HEARTBEAT_INTERVAL_SECONDS = 10
# A run is never retried silently: a dead scanner leaves it to the reconciliation (CU-23).
JOB_RETRIES = 1
# The error SAQ keeps on a job the analyst cancelled.
ABORT_REASON = "cancelled_by_user"
TERMINAL_JOB_STATUSES = (Status.COMPLETE, Status.FAILED, Status.ABORTED)


class QueueUnavailableError(Exception):
    """Redis did not accept the job. The run must not stay `queued` without one (RN-07)."""


class RunQueue(Protocol):
    async def enqueue(self, run_id: UUID) -> str:
        """Enqueues the run and returns the job key."""
        ...

    async def abort(self, run_id: UUID) -> None:
        """Stops the run's job: SAQ cancels its task in about a second (RF-52, PT-02). A job that
        is already gone (finished, or lost with a dead scanner) is left alone."""
        ...

    async def close(self) -> None: ...


def job_key(run_id: UUID) -> str:
    return f"run:{run_id}"


class SaqRunQueue:
    def __init__(self, queue: Queue) -> None:
        self.queue = queue

    @classmethod
    def from_url(cls, url: str) -> "SaqRunQueue":
        return cls(Queue.from_url(url, name=QUEUE_NAME))

    async def enqueue(self, run_id: UUID) -> str:
        key = job_key(run_id)
        try:
            job = await self.queue.enqueue(
                EXECUTE_RUN,
                key=key,
                run_id=str(run_id),
                timeout=JOB_TIMEOUT_SECONDS,
                heartbeat=JOB_HEARTBEAT_SECONDS,
                retries=JOB_RETRIES,
            )
        except (RedisError, OSError, TimeoutError) as error:
            # Only the type: the message may include the Redis host.
            raise QueueUnavailableError(type(error).__name__) from error
        if job is None:  # a job with that key already exists: the same run, enqueued twice
            return key
        return job.key

    async def abort(self, run_id: UUID) -> None:
        try:
            job = await self.queue.job(job_key(run_id))
            if job is not None and job.status not in TERMINAL_JOB_STATUSES:
                await self.queue.abort(job, error=ABORT_REASON)
        except (RedisError, OSError, TimeoutError) as error:
            raise QueueUnavailableError(type(error).__name__) from error

    async def close(self) -> None:
        # Shutting down with Redis gone must not fail: there is nothing left to release.
        with contextlib.suppress(RedisError, OSError):
            await self.queue.disconnect()


class UnconfiguredRunQueue:
    """Without `HINDAMA_REDIS_URL` the API still serves everything but launching runs."""

    async def enqueue(self, run_id: UUID) -> str:
        raise QueueUnavailableError("redis_url is not set")

    async def abort(self, run_id: UUID) -> None:
        raise QueueUnavailableError("redis_url is not set")

    async def close(self) -> None:
        return None
