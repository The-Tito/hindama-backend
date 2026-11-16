"""Testing a credential against the analyst's API (RF-30, RF-32) through the SSRF guard (ADR-008).

A local server on loopback stands in for the API, under the fictitious host `api.hindama.test`.
"""

import asyncio
import json
from collections.abc import Iterator
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from hindama.core.credentials import Credential
from hindama.core.identity_probe import (
    DEFAULT_LOGIN_FIELDS,
    Failure,
    IdentityProber,
    IncompleteCredentialError,
    LoginRequest,
    Probe,
    credential_headers,
    find_token,
    login_fields,
)
from hindama.models.enums import AuthType
from tests.dns import FakeResolver
from tests.servers import HOST, LOOPBACK, LocalServer, UnresolvedResolver, allow_loopback

TOKEN = "token-de-prueba-9f2a"
PASSWORD = "contraseña"  # the local server's fictitious account
SEEN: list[dict[str, Any]] = []


async def orders(request: Request) -> Response:
    SEEN.append({"path": "/orders", "headers": dict(request.headers)})
    allowed = (
        request.headers.get("authorization") == f"Bearer {TOKEN}"
        or request.cookies.get("sesion") == TOKEN
        or request.headers.get("x-api-key") == TOKEN
    )
    return JSONResponse({"ok": allowed}, status_code=200 if allowed else 401)


async def login(request: Request) -> Response:
    body = await request.json()
    SEEN.append({"path": "/login", "body": body, "headers": dict(request.headers)})
    if body == {"email": "ana@ejemplo.com", "password": PASSWORD}:
        return JSONResponse({"data": {"access_token": TOKEN}})
    if body.get("email") == "sin-token@ejemplo.com":
        return JSONResponse({"mensaje": "hola"})
    return JSONResponse({"error": "credenciales"}, status_code=401)


async def moved(_: Request) -> Response:
    return RedirectResponse("/orders", status_code=302)


async def huge(_: Request) -> Response:
    return Response(b"x" * (2 * 1024 * 1024), status_code=200)


async def slow(_: Request) -> Response:
    await asyncio.sleep(2)
    return Response(b"tarde")


APP = Starlette(
    routes=[
        Route("/orders", orders),
        Route("/login", login, methods=["POST"]),
        Route("/moved", moved),
        Route("/huge", huge),
        Route("/slow", slow),
    ]
)


@pytest.fixture(scope="module")
def server() -> Iterator[LocalServer]:
    with LocalServer(APP) as running:
        yield running


@pytest.fixture(autouse=True)
def nothing_seen() -> None:
    SEEN.clear()


@pytest.fixture
def prober() -> IdentityProber:
    resolver = FakeResolver()
    resolver.set(HOST, LOOPBACK)
    return IdentityProber(resolver=resolver, address_policy=allow_loopback)


def url(server: LocalServer, path: str = "/orders") -> str:
    return f"http://{HOST}:{server.port}{path}"


def bearer(server: LocalServer, path: str = "/orders", token: str = TOKEN) -> Probe:
    return Probe(HOST, url(server, path), AuthType.BEARER, Credential(token=token))


# ------------------------------------------------------------------ pure helpers


def test_login_fields_follow_the_declared_names() -> None:
    assert login_fields(["Email", "Password", "recordar"]) == ("Email", "Password")
    assert login_fields(["usuario", "clave"]) == ("usuario", "clave")
    assert login_fields([]) == DEFAULT_LOGIN_FIELDS
    assert login_fields(["user", "otro"]) == ("user", "password")


@pytest.mark.parametrize(
    ("body", "token"),
    [
        (b'{"access_token": "abc"}', "abc"),
        (b'{"token": "abc", "access_token": "def"}', "def"),  # access_token first
        (b'{"data": {"jwt": "abc"}}', "abc"),
        (b'{"tokens": {"idToken": "abc"}}', "abc"),
        (b'{"token": ""}', None),
        (b'{"token": 123}', None),
        (b'{"token": "a\\nb"}', None),  # a header could not carry it
        (b'{"token": " abc"}', None),
        (b'{"otro": "abc"}', None),
        (b'["abc"]', None),
        (b"no es json", None),
        (b"[" * 100_000, None),  # too deep for the parser
    ],
)
def test_find_token(body: bytes, token: str | None) -> None:
    assert find_token(body) == token


def test_long_tokens_are_refused() -> None:
    assert find_token(json.dumps({"token": "a" * 4097}).encode()) is None


def test_headers_of_each_kind() -> None:
    value = Credential(value="ñandú-1234")
    assert credential_headers(AuthType.BEARER, Credential(token="t"), None) == {
        b"Authorization": b"Bearer t"
    }
    assert credential_headers(AuthType.LOGIN, Credential(username="u", password="p"), None, "t")
    assert credential_headers(AuthType.COOKIE, value, "sesion") == {
        b"Cookie": "sesion=ñandú-1234".encode()
    }
    assert credential_headers(AuthType.HEADER, value, "X-Api-Key") == {
        b"X-Api-Key": "ñandú-1234".encode()
    }


@pytest.mark.parametrize(
    ("kind", "credential", "field_name"),
    [
        (AuthType.LOGIN, Credential(username="u", password="p"), None),  # no token
        (AuthType.BEARER, Credential(value="v"), None),
        (AuthType.COOKIE, Credential(value="v"), None),
        (AuthType.NONE, Credential(value="v"), "x"),
    ],
)
def test_an_incomplete_credential_is_a_bug(
    kind: AuthType, credential: Credential, field_name: str | None
) -> None:
    with pytest.raises(IncompleteCredentialError):
        credential_headers(kind, credential, field_name)


# ------------------------------------------------------------------ against the local server


async def test_a_working_token(server: LocalServer, prober: IdentityProber) -> None:
    result = await prober.probe(bearer(server))
    assert (result.succeeded, result.status_code, result.failure) == (True, 200, None)
    assert SEEN[0]["headers"]["authorization"] == f"Bearer {TOKEN}"


async def test_a_rejected_token_reports_the_status(
    server: LocalServer, prober: IdentityProber
) -> None:
    result = await prober.probe(bearer(server, token="otro"))
    assert (result.succeeded, result.status_code, result.failure) == (False, 401, Failure.REJECTED)


async def test_cookie_and_header(server: LocalServer, prober: IdentityProber) -> None:
    for kind, name in ((AuthType.COOKIE, "sesion"), (AuthType.HEADER, "X-Api-Key")):
        probe = Probe(HOST, url(server), kind, Credential(value=TOKEN), field_name=name)
        assert (await prober.probe(probe)).status_code == 200


async def test_a_non_ascii_value_is_sent_not_a_crash(
    server: LocalServer, prober: IdentityProber
) -> None:
    probe = Probe(HOST, url(server), AuthType.HEADER, Credential(value="ñandú"), "X-Api-Key")
    assert (await prober.probe(probe)).failure == Failure.REJECTED


async def test_redirects_are_answers_not_followed(
    server: LocalServer, prober: IdentityProber
) -> None:
    """The credential is never resent to where a 3xx points."""
    result = await prober.probe(bearer(server, "/moved"))
    assert (result.status_code, result.failure) == (302, Failure.REJECTED)
    assert SEEN == []


async def test_a_huge_answer_still_counts_by_its_status(
    server: LocalServer, prober: IdentityProber
) -> None:
    assert (await prober.probe(bearer(server, "/huge"))).succeeded


def login_probe(server: LocalServer, username: str, password: str = PASSWORD) -> Probe:
    return Probe(
        HOST,
        url(server),
        AuthType.LOGIN,
        Credential(username=username, password=password),
        login=LoginRequest(url(server, "/login"), "email", "password"),
    )


async def test_automatic_login_then_the_token(server: LocalServer, prober: IdentityProber) -> None:
    result = await prober.probe(login_probe(server, "ana@ejemplo.com"))
    assert (result.succeeded, result.status_code) == (True, 200)
    assert SEEN[0]["body"] == {"email": "ana@ejemplo.com", "password": PASSWORD}
    assert SEEN[0]["headers"]["content-type"] == "application/json"
    assert SEEN[1]["headers"]["authorization"] == f"Bearer {TOKEN}"


async def test_a_refused_login(server: LocalServer, prober: IdentityProber) -> None:
    result = await prober.probe(login_probe(server, "ana@ejemplo.com", "mala"))
    assert (result.status_code, result.failure) == (401, Failure.LOGIN_FAILED)
    assert len(SEEN) == 1  # the protected operation is not called


async def test_a_login_without_a_token(server: LocalServer, prober: IdentityProber) -> None:
    result = await prober.probe(login_probe(server, "sin-token@ejemplo.com"))
    assert (result.status_code, result.failure) == (200, Failure.LOGIN_FAILED)


async def test_a_login_with_a_huge_answer(server: LocalServer, prober: IdentityProber) -> None:
    probe = login_probe(server, "ana@ejemplo.com")
    probe = Probe(
        probe.host,
        probe.url,
        probe.auth_type,
        probe.credential,
        login=LoginRequest(url(server, "/huge"), "email", "password"),
    )
    assert (await prober.probe(probe)).failure == Failure.LOGIN_FAILED


async def test_a_login_without_its_request_is_a_bug(
    server: LocalServer, prober: IdentityProber
) -> None:
    probe = Probe(HOST, url(server), AuthType.LOGIN, Credential(username="u", password="p"))
    with pytest.raises(IncompleteCredentialError):
        await prober.probe(probe)


# ------------------------------------------------------------------ failures without an answer


async def test_loopback_is_not_allowed_in_production(server: LocalServer) -> None:
    resolver = FakeResolver()
    resolver.set(HOST, LOOPBACK)
    result = await IdentityProber(resolver=resolver).probe(bearer(server))
    assert (result.status_code, result.failure) == (None, Failure.DESTINATION_NOT_ALLOWED)
    assert SEEN == []


async def test_an_unresolved_host_is_a_connection_error(server: LocalServer) -> None:
    result = await IdentityProber(resolver=UnresolvedResolver()).probe(bearer(server))
    assert (result.status_code, result.failure) == (None, Failure.CONNECTION_ERROR)


async def test_a_closed_port_is_a_connection_error(prober: IdentityProber) -> None:
    probe = Probe(HOST, f"http://{HOST}:1/orders", AuthType.BEARER, Credential(token=TOKEN))
    assert (await prober.probe(probe)).failure == Failure.CONNECTION_ERROR


async def test_the_whole_test_has_a_deadline(server: LocalServer) -> None:
    resolver = FakeResolver()
    resolver.set(HOST, LOOPBACK)
    prober = IdentityProber(resolver=resolver, address_policy=allow_loopback, timeout=0.2)
    assert (await prober.probe(bearer(server, "/slow"))).failure == Failure.CONNECTION_ERROR
