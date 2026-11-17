"""The detectors of Configuration, API8 (RF-55; catalog, section 7.1)."""

import uuid

import pytest

from hindama.models.enums import AuthType, HttpMethod, IdentityRole, Policy
from hindama.scanner.context import Actor, RunContext, Target
from hindama.scanner.evidence import Exchange
from hindama.scanner.modules.configuration import (
    FRAMES,
    HSTS,
    INTERNAL_DETAILS,
    MALFORMED,
    NOSNIFF,
    UNTRUSTED_ORIGIN,
    Configuration,
    _cors_accepts_anyone,
    _discloses_version,
    _main_path,
    _malformed_paths,
    _missing_headers,
)


def answer(*headers: tuple[str, str], status: int = 200, body: bytes = b"{}") -> Exchange:
    return Exchange("GET", "https://api.x/", {}, status, headers, body)


HARDENED = (
    ("Strict-Transport-Security", "max-age=31536000"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
)


def test_hsts_is_required_only_over_https() -> None:
    bare = answer()

    assert HSTS in _missing_headers(bare, secure=True)
    assert HSTS not in _missing_headers(bare, secure=False)
    assert _missing_headers(answer(*HARDENED), secure=True) == []


def test_nosniff_must_say_nosniff() -> None:
    wrong = answer(("X-Content-Type-Options", "sniff-away"), ("X-Frame-Options", "DENY"))

    assert _missing_headers(wrong, secure=False) == [NOSNIFF]


def test_frame_ancestors_in_the_csp_protects_from_frames() -> None:
    csp = answer(
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
    )

    assert FRAMES not in _missing_headers(csp, secure=False)
    assert FRAMES in _missing_headers(answer(("X-Content-Type-Options", "nosniff")), secure=False)


@pytest.mark.parametrize(
    ("origin", "credentials", "accepted"),
    [
        (UNTRUSTED_ORIGIN, "true", True),
        ("*", "true", True),
        (UNTRUSTED_ORIGIN, None, False),  # without credentials, a public API may allow anyone
        ("https://app.propia.com", "true", False),
        (None, "true", False),
    ],
)
def test_cors_with_credentials(origin: str | None, credentials: str | None, accepted: bool) -> None:
    headers = []
    if origin is not None:
        headers.append(("Access-Control-Allow-Origin", origin))
    if credentials is not None:
        headers.append(("Access-Control-Allow-Credentials", credentials))

    assert _cors_accepts_anyone(answer(*headers)) is accepted


@pytest.mark.parametrize(
    ("header", "disclosed"),
    [
        (("Server", "nginx/1.25.3"), True),
        (("X-Powered-By", "PHP/8.1.2"), True),
        (("Server", "nginx"), False),
        (("Server", "uvicorn"), False),
        (("X-Request-Id", "1.2"), False),  # only Server and X-Powered-By
    ],
)
def test_versions_in_headers(header: tuple[str, str], disclosed: bool) -> None:
    assert _discloses_version(answer(header)) is disclosed


@pytest.mark.parametrize(
    "body",
    [
        'Traceback (most recent call last):\n  File "/app/main.py", line 3, in f',
        "java.lang.NullPointerException\n\tat com.shop.Orders.get(Orders.java:42)",
        'Exception in thread "main" java.lang.IllegalStateException',
        "TypeError: x is undefined\n    at Object.<anonymous> (/srv/app/index.js:10:5)",
        "Fatal error: Uncaught Error in /var/www/html/index.php on line 7",
        "SQLSTATE[42000]: Syntax error or access violation",
        "ORA-00933: SQL command not properly ended",
        "You have an error in your SQL syntax; check the manual",
        "psycopg2.errors.UndefinedTable: relation does not exist",
        "Server Error in '/' Application.",
        "could not open /usr/src/app/config.yaml",
        "C:\\\\inetpub\\\\wwwroot\\\\web.config",
    ],
)
def test_internal_details_are_recognised(body: str) -> None:
    assert INTERNAL_DETAILS.search(body)


@pytest.mark.parametrize(
    "body",
    [
        '{"detail": "Not Found"}',
        '{"error": "internal", "request_id": "01a1e714"}',
        "Bad Request",
        '{"message": "invoice must be a number"}',
    ],
)
def test_ordinary_errors_are_not_details(body: str) -> None:
    assert INTERNAL_DETAILS.search(body) is None


def context(*targets: Target) -> RunContext:
    anonymous = Actor(uuid.uuid4(), "anónima", IdentityRole.OTHER, AuthType.NONE, None)
    return RunContext(
        uuid.uuid4(), uuid.uuid4(), "https://api.x", "api.x", list(targets), [anonymous]
    )


def target(method: HttpMethod, path: str) -> Target:
    return Target(uuid.uuid4(), method, path, Policy.AUTHENTICATED, ())


def test_the_paths_it_asks_for() -> None:
    ctx = context(
        target(HttpMethod.POST, "/orders"),
        target(HttpMethod.GET, "/a/{id}"),
        target(HttpMethod.GET, "/health"),
        target(HttpMethod.GET, "/b/{id}/c/{other}"),
        target(HttpMethod.DELETE, "/a/{id}"),
        target(HttpMethod.GET, "/c/{id}"),
        target(HttpMethod.GET, "/d/{id}"),
    )

    assert _main_path(ctx) == "/health"
    assert _malformed_paths(ctx) == [
        f"/a/{MALFORMED}",
        f"/b/{MALFORMED}/c/{MALFORMED}",
        f"/c/{MALFORMED}",
    ]  # at most 3, only GET
    assert _main_path(context()) == ""  # no contract: the base URL itself
    assert "'" not in MALFORMED and '"' not in MALFORMED  # no SQL: that is another module


def test_one_cell_for_the_whole_api() -> None:
    cells = Configuration().plan(context(target(HttpMethod.GET, "/a")))

    assert [(cell.target, cell.actor.auth_type) for cell in cells] == [(None, AuthType.NONE)]
    assert Configuration().plan(RunContext(uuid.uuid4(), uuid.uuid4(), "h", "h", [], [])) == []
