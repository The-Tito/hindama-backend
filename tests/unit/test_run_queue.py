"""The run queue when Redis is missing (ADR-012): the API must answer 503, never hang or leak."""

import uuid

import pytest

from hindama.core.run_queue import QueueUnavailableError, SaqRunQueue, UnconfiguredRunQueue


async def test_an_unreachable_redis_is_unavailable() -> None:
    queue = SaqRunQueue.from_url("redis://:clave-secreta@127.0.0.1:1/0")

    with pytest.raises(QueueUnavailableError) as raised:
        await queue.enqueue(uuid.uuid4())

    assert "clave-secreta" not in str(raised.value)
    assert "127.0.0.1" not in str(raised.value)
    await queue.close()


async def test_without_redis_url_launching_is_unavailable() -> None:
    with pytest.raises(QueueUnavailableError):
        await UnconfiguredRunQueue().enqueue(uuid.uuid4())
