"""The pieces of the scanner that need no database: limiter (RF-47), evidence (RF-66, RF-67, RN-11)
and the judgement of object access (RF-61)."""

import asyncio
import datetime as dt
import json

import pytest

from hindama.models.base import MAX_EVIDENCE_BYTES
from hindama.scanner.evidence import MAX_BODY_BYTES, Exchange, Masker, mask
from hindama.scanner.limiter import BudgetExhaustedError, RequestLimiter
from hindama.scanner.modules import ALLOWED, DENIED, NO_DATA, fill, path_parameters
from hindama.scanner.modules.object_access import _carries, _judge
from hindama.scanner.recorder import _monday

# ------------------------------------------------------------------ limiter


async def test_requests_are_spaced_at_the_rate() -> None:
    limiter = RequestLimiter(requests_per_second=20, concurrency=5, max_requests=100)
    loop = asyncio.get_running_loop()
    start = loop.time()

    for _ in range(5):
        async with limiter.slot():
            pass

    assert loop.time() - start >= 4 / 20 * 0.9  # the first goes at once, then one every 50 ms
    assert limiter.sent == 5


async def test_concurrency_is_capped() -> None:
    limiter = RequestLimiter(requests_per_second=20, concurrency=2, max_requests=100)
    inside = peak = 0

    async def request() -> None:
        nonlocal inside, peak
        async with limiter.slot():
            inside += 1
            peak = max(peak, inside)
            await asyncio.sleep(0.05)
            inside -= 1

    await asyncio.gather(*(request() for _ in range(6)))

    assert peak == 2


async def test_the_budget_stops_the_requests() -> None:
    limiter = RequestLimiter(requests_per_second=20, concurrency=1, max_requests=2)
    for _ in range(2):
        async with limiter.slot():
            pass

    with pytest.raises(BudgetExhaustedError):
        async with limiter.slot():
            pass  # pragma: no cover - never reached
    assert limiter.sent == 2


# ------------------------------------------------------------------ evidence


def exchange(body: bytes = b"{}", **headers: str) -> Exchange:
    return Exchange(
        method="GET",
        url="http://api.hindama.test/orders/1",
        request_headers=headers,
        status_code=200,
        response_headers=(("content-type", "application/json"), ("set-cookie", "s=abcdefghijk")),
        body=body,
    )


@pytest.mark.parametrize(
    ("value", "shown"), [("abcdefghijkl", "****ijkl"), ("abcdefgh", "****"), ("", "****")]
)
def test_mask_shows_only_the_last_four(value: str, shown: str) -> None:
    assert mask(value) == shown


def test_credentials_are_masked_in_headers_and_bodies() -> None:
    masker = Masker(secrets=["token-secreto-123456"], header_names=["X-Llave"])
    masker.add("token-de-login-abcdef")
    body = json.dumps({"echo": "token-secreto-123456", "again": "token-de-login-abcdef"}).encode()

    evidence = masker.evidence(
        exchange(body, authorization="Bearer token-secreto-123456", **{"X-Llave": "valor-llave-99"})
    )

    stored = json.dumps(evidence)
    assert "token-secreto" not in stored
    assert "token-de-login" not in stored
    assert evidence["request"]["headers"]["authorization"] == "****3456"
    assert evidence["request"]["headers"]["x-llave"] == "****e-99"
    assert evidence["response"]["headers"]["set-cookie"] == "****hijk"
    assert evidence["response"]["headers"]["content-type"] == "application/json"


def test_a_secret_inside_another_is_replaced_whole() -> None:
    masker = Masker(secrets=["abcd1234", "xxabcd1234yy"])

    assert masker.text("xxabcd1234yy") == "****34yy"


def test_bodies_are_truncated_to_ten_kilobytes() -> None:
    evidence = Masker().evidence(exchange(b"a" * (MAX_BODY_BYTES + 100)))

    assert len(evidence["response"]["body"]) == MAX_BODY_BYTES
    assert evidence["response"]["body_truncated"] is True


def test_evidence_always_fits_in_the_database() -> None:
    evidence = Masker().evidence(exchange(b"\x00" * MAX_BODY_BYTES), note="x")

    assert len(json.dumps(evidence).encode()) <= MAX_EVIDENCE_BYTES
    assert evidence["note"] == "x"


def test_headers_are_capped() -> None:
    many = [(f"x-{n}", "v" * 1000) for n in range(80)]

    shown = Masker().headers(many)

    assert len(shown) == 50
    assert all(len(value) == 500 for value in shown.values())


def test_an_exchange_never_shows_its_headers() -> None:
    assert "Bearer" not in repr(exchange(authorization="Bearer token-secreto-123456"))


# ------------------------------------------------------------------ object access (RF-61)


def test_paths_are_filled_one_segment_per_value() -> None:
    path = "/users/{user_id}/orders/{order_id}"

    assert path_parameters(path) == ["user_id", "order_id"]
    assert fill(path, {"user_id": "a/b", "order_id": "1 2"}) == "/users/a%2Fb/orders/1%202"


@pytest.mark.parametrize(
    ("body", "value", "carried"),
    [
        (b'{"id": "ord-1"}', "ord-1", True),
        (b'{"data": [{"id": 42}]}', "42", True),
        (b'{"id": "ord-10"}', "ord-1", False),  # a whole value, not a prefix
        (b'{"active": true}', "True", False),  # booleans are not identifiers
        (b"<p>ord-1</p>", "ord-1", True),
        (b"<p>42</p>", "42", False),  # too short to search outside JSON
    ],
)
def test_the_body_must_carry_the_identifier(body: bytes, value: str, carried: bool) -> None:
    assert _carries(body, value) is carried


@pytest.mark.parametrize(
    ("status", "body", "word"),
    [
        (200, b'{"id": "ord-1", "total": 3}', ALLOWED),
        (200, b'{"same": "as the owner"}', ALLOWED),
        (200, b'{"error": "not_found"}', NO_DATA),  # the decoy of the catalog
        (204, b"", NO_DATA),
        (403, b'{"id": "ord-1"}', DENIED),
        (404, b"", DENIED),
    ],
)
def test_the_judgement(status: int, body: bytes, word: str) -> None:
    baseline = exchange(b'{"same": "as the owner"}')
    attack = Exchange("GET", "http://x/o", {}, status, (), body)

    assert _judge(attack, baseline, "ord-1") == word


def test_metrics_keep_only_the_monday() -> None:
    assert _monday(dt.date(2026, 11, 19)) == dt.date(2026, 11, 16)
    assert _monday(dt.date(2026, 11, 16)) == dt.date(2026, 11, 16)


def test_the_dashboard_and_the_scanner_agree_on_the_implemented_modules() -> None:
    """RF-45: a module the scanner lacks is `not_implemented`, never a run of zero cells."""
    from hindama.scanner.execution import MODULES
    from hindama.services.projects import IMPLEMENTED_MODULES

    assert set(MODULES) == IMPLEMENTED_MODULES
