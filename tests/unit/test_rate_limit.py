"""At most 100 requests per minute per user to the platform's API (RNF-09): 429 with `Retry-After`.

Through the app with a limiter in memory and a clock the tests move; the Redis limiter is checked
against a real Redis when `HINDAMA_TEST_REDIS_URL` is set (as in CI).
"""

import os
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import structlog
from fastapi import FastAPI
from redis.asyncio import Redis

from hindama.api import middleware
from hindama.config import Settings
from hindama.core.rate_limit import MemoryRateLimiter, RedisRateLimiter
from hindama.main import create_app
from tests.tokens import FakeUserPool

LIMIT = 3
ANA, BETO = "0192e3a0-aaaa-7000-8000-00000000000a", "0192e3a0-aaaa-7000-8000-00000000000b"


class Clock:
    def __init__(self, now: float = 60 * 16_667 + 20.0) -> None:  # 20 s into a minute
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def app(settings: Settings, user_pool: FakeUserPool, clock: Clock) -> FastAPI:
    return create_app(
        settings,
        verifier=user_pool.verifier(),
        profiles=user_pool.profile_client(),
        rate_limiter=MemoryRateLimiter(LIMIT, clock),
    )


@pytest.fixture
async def http(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def get(http: httpx.AsyncClient, user_pool: FakeUserPool, sub: str) -> httpx.Response:
    # A missing route: authenticated, routed and answered without the database.
    headers = {"Authorization": f"Bearer {user_pool.token(sub=sub)}"}
    return await http.get("/nothing-here", headers=headers)


async def test_over_the_limit_answers_429_until_the_minute_ends(
    http: httpx.AsyncClient, user_pool: FakeUserPool, clock: Clock
) -> None:
    allowed = [await get(http, user_pool, ANA) for _ in range(LIMIT)]

    refused = await get(http, user_pool, ANA)

    assert {r.status_code for r in allowed} == {404}
    assert refused.status_code == 429
    assert refused.headers["Retry-After"] == "40"  # the rest of the minute
    assert refused.headers["Content-Type"] == "application/problem+json"
    body = refused.json()
    assert body["code"] == "rate_limit.exceeded"
    assert body["status"] == 429
    assert body["request_id"] == refused.headers["X-Request-Id"]
    clock.now += 40  # the next window
    assert (await get(http, user_pool, ANA)).status_code == 404


async def test_each_user_has_its_own_count(
    http: httpx.AsyncClient, user_pool: FakeUserPool
) -> None:
    for _ in range(LIMIT + 1):
        await get(http, user_pool, ANA)

    assert (await get(http, user_pool, BETO)).status_code == 404


async def test_without_a_session_nothing_is_counted(
    http: httpx.AsyncClient, user_pool: FakeUserPool
) -> None:
    for _ in range(LIMIT + 2):
        assert (await http.get("/nothing-here")).status_code == 401
        assert (await http.get("/health")).status_code in (200, 503)

    assert (await get(http, user_pool, ANA)).status_code == 404


async def test_a_refusal_is_logged_without_the_user(
    http: httpx.AsyncClient, user_pool: FakeUserPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(middleware, "log", structlog.get_logger("test"))
    for _ in range(LIMIT):
        await get(http, user_pool, ANA)

    with structlog.testing.capture_logs() as logs:
        await get(http, user_pool, ANA)

    limited = [e for e in logs if e["event"] == "rate_limited"]
    assert limited == [
        {"event": "rate_limited", "path": "/nothing-here", "retry_after": 40, "log_level": "info"}
    ]


def test_the_default_limit_is_one_hundred(settings: Settings) -> None:
    assert settings.rate_limit_per_minute == 100


# ------------------------------------------------------------------ Redis


REDIS_URL = os.environ.get("HINDAMA_TEST_REDIS_URL")


@pytest.mark.skipif(REDIS_URL is None, reason="HINDAMA_TEST_REDIS_URL is not set")
async def test_redis_counts_per_user_and_window() -> None:
    assert REDIS_URL is not None
    clock = Clock()
    limiter = RedisRateLimiter(Redis.from_url(REDIS_URL), LIMIT, clock)
    user, other = str(uuid.uuid4()), str(uuid.uuid4())
    try:
        results = [await limiter.hit(user) for _ in range(LIMIT + 1)]
        other_result = await limiter.hit(other)
        ttl = await limiter.redis.ttl(f"rate:{user}:{int(clock.now // 60)}")
        clock.now += 40
        next_window = await limiter.hit(user)
    finally:
        await limiter.close()

    assert results == [None] * LIMIT + [40]
    assert other_result is None
    assert 0 < ttl <= 120  # the keys expire on their own
    assert next_window is None


async def test_without_redis_requests_go_through(monkeypatch: pytest.MonkeyPatch) -> None:
    from hindama.core import rate_limit

    monkeypatch.setattr(rate_limit, "log", structlog.get_logger("test"))
    limiter = RedisRateLimiter(Redis.from_url("redis://127.0.0.1:1/0"), 1)
    try:
        with structlog.testing.capture_logs() as logs:
            results = [await limiter.hit("ana") for _ in range(3)]
    finally:
        await limiter.close()

    assert results == [None, None, None]
    assert logs[0]["event"] == "rate_limit_unavailable"
    assert "127.0.0.1" not in str(logs)  # only the type of the error
