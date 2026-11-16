"""Ownership verification (CU-07; RF-18, RF-21): the file through the SSRF guard and the TXT record.

The "user's API" is a local HTTPS server for `api.hindama.test`; DNS answers are scripted.
"""

import asyncio
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdata
import dns.resolver
import pytest
import trustme
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from hindama.core import ownership
from hindama.core.ownership import (
    CheckResult,
    NetworkOwnershipChecker,
    Outcome,
    SystemTxtResolver,
    TxtLookupError,
    dns_name,
    file_url,
    published_code,
    summarize,
)
from hindama.models.enums import VerificationMethod
from tests.ownership import FakeTxtResolver
from tests.servers import (
    HOST,
    LOOPBACK,
    LocalServer,
    ScriptedResolver,
    UnresolvedResolver,
    allow_loopback,
    trusting,
)
from tests.servers import https_server as serve_https

CODE = published_code("8f3a1c9e2b7d4f60a5e1c3b9d7f2a4e6")

# What the local server answers on /.well-known/hindama-verificacion.txt; reset by each test.
FILE: dict[str, Any] = {}


async def well_known(_: Request) -> Response:
    if "redirect" in FILE:
        return RedirectResponse(FILE["redirect"])
    return Response(FILE["body"], status_code=FILE["status"], media_type="text/plain")


APP = Starlette(routes=[Route("/.well-known/hindama-verificacion.txt", well_known)])


@pytest.fixture(autouse=True)
def published() -> Iterator[None]:
    FILE.clear()
    FILE.update(status=200, body=f"{CODE}\n")
    yield


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="module")
def server(ca: trustme.CA, tmp_path_factory: pytest.TempPathFactory) -> Iterator[LocalServer]:
    with serve_https(APP, ca, Path(tmp_path_factory.mktemp("tls"))) as running:
        yield running


@pytest.fixture
def txt() -> FakeTxtResolver:
    return FakeTxtResolver()


def checker(
    txt: FakeTxtResolver | None = None,
    *,
    resolver: object | None = None,
    ca: trustme.CA | None = None,
    policy: bool = True,
) -> NetworkOwnershipChecker:
    return NetworkOwnershipChecker(
        resolver=resolver or ScriptedResolver([LOOPBACK]),  # type: ignore[arg-type]
        txt_resolver=txt or FakeTxtResolver(),
        ssl_context=trusting(ca) if ca else None,
        address_policy=allow_loopback if policy else None,
    )


def base_url(server: LocalServer, scheme: str = "https") -> str:
    return f"{scheme}://{HOST}:{server.port}/v1/tienda"


async def check_file(server: LocalServer, ca: trustme.CA | None, **options: Any) -> CheckResult:
    return await checker(ca=ca, **options).check(
        VerificationMethod.FILE, base_url=base_url(server), host=HOST, code=CODE
    )


# ---------------------------------------------------------------- instructions


def test_the_file_lives_at_the_root_of_the_base_url_host_and_port() -> None:
    assert (
        file_url("https://api.ejemplo.com:8443/v1/pedidos?x=1")
        == "https://api.ejemplo.com:8443/.well-known/hindama-verificacion.txt"
    )
    assert file_url("http://api.ejemplo.com/") == (
        "http://api.ejemplo.com/.well-known/hindama-verificacion.txt"
    )


def test_the_txt_record_is_under_the_exact_host() -> None:
    assert dns_name("api.ejemplo.com") == "_hindama-verificacion.api.ejemplo.com"


def test_the_published_code_has_a_recognizable_prefix() -> None:
    assert CODE == "hindama-verificacion=8f3a1c9e2b7d4f60a5e1c3b9d7f2a4e6"


def test_found_is_printable_and_short() -> None:
    assert summarize("a\x00b\x1b[31mc\n") == "a b [31mc"
    long = summarize("x" * 500)
    assert len(long) == 200
    assert long.endswith("…")


# ---------------------------------------------------------------- file


async def test_the_published_file_verifies(server: LocalServer, ca: trustme.CA) -> None:
    FILE["body"] = f"﻿  {CODE}\r\n"  # BOM and spaces around: editors add them
    assert await check_file(server, ca) == CheckResult(Outcome.VERIFIED)


async def test_a_missing_file(server: LocalServer, ca: trustme.CA) -> None:
    FILE.update(status=404, body="Not found")
    assert await check_file(server, ca) == CheckResult(Outcome.FILE_NOT_FOUND, "HTTP 404")


async def test_a_large_error_page_is_still_a_missing_file(
    server: LocalServer, ca: trustme.CA
) -> None:
    FILE.update(status=404, body="<html>" + "x" * 5000)
    assert await check_file(server, ca) == CheckResult(Outcome.FILE_NOT_FOUND, "HTTP 404")


async def test_another_content(server: LocalServer, ca: trustme.CA) -> None:
    FILE["body"] = "hindama-verificacion=000000"
    assert await check_file(server, ca) == CheckResult(
        Outcome.CONTENT_MISMATCH, "HTTP 200: hindama-verificacion=000000"
    )


async def test_the_code_must_be_the_whole_content(server: LocalServer, ca: trustme.CA) -> None:
    FILE["body"] = f"{CODE}\notra línea"
    result = await check_file(server, ca)
    assert result.outcome == Outcome.CONTENT_MISMATCH


async def test_a_file_over_1_kib_is_not_read(server: LocalServer, ca: trustme.CA) -> None:
    FILE["body"] = CODE + " " * 2000
    assert await check_file(server, ca) == CheckResult(
        Outcome.CONTENT_MISMATCH, "HTTP 200: más de 1 KiB"
    )


async def test_a_redirect_to_another_host_is_not_followed(
    server: LocalServer, ca: trustme.CA
) -> None:
    FILE["redirect"] = "https://169.254.169.254/latest/meta-data/"
    assert await check_file(server, ca) == CheckResult(Outcome.DESTINATION_NOT_ALLOWED)


async def test_a_private_address_is_never_contacted(server: LocalServer, ca: trustme.CA) -> None:
    # Production policy: the host resolves to loopback, where the server listens. With nothing to
    # serve, a request that got through would come back as a 500, not as a blocked destination.
    FILE.clear()
    assert await check_file(server, ca, policy=False) == CheckResult(
        Outcome.DESTINATION_NOT_ALLOWED
    )


async def test_a_host_that_does_not_resolve(server: LocalServer, ca: trustme.CA) -> None:
    result = await check_file(server, ca, resolver=UnresolvedResolver())
    assert result == CheckResult(Outcome.CONNECTION_ERROR)


async def test_an_untrusted_certificate_is_a_connection_error(server: LocalServer) -> None:
    assert await check_file(server, None) == CheckResult(Outcome.CONNECTION_ERROR)


async def test_a_closed_port_is_a_connection_error() -> None:
    unused = socket.socket()
    unused.bind((LOOPBACK, 0))
    port = unused.getsockname()[1]
    unused.close()
    result = await checker().check(
        VerificationMethod.FILE, base_url=f"http://{HOST}:{port}", host=HOST, code=CODE
    )
    assert result == CheckResult(Outcome.CONNECTION_ERROR)


async def test_the_whole_check_has_a_time_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    class SlowTxt:
        async def txt(self, name: str) -> list[str]:
            await asyncio.sleep(5)
            return []

    monkeypatch.setattr(ownership, "CHECK_TIMEOUT_SECONDS", 0.05)
    slow = NetworkOwnershipChecker(resolver=ScriptedResolver([LOOPBACK]), txt_resolver=SlowTxt())
    result = await slow.check(VerificationMethod.DNS, base_url="https://x", host=HOST, code=CODE)
    assert result == CheckResult(Outcome.CONNECTION_ERROR)


# ---------------------------------------------------------------- DNS


async def test_a_txt_record_with_the_code_verifies(txt: FakeTxtResolver) -> None:
    txt.records[dns_name(HOST)] = ["v=spf1 -all", f" {CODE} "]
    result = await checker(txt).check(VerificationMethod.DNS, base_url="", host=HOST, code=CODE)
    assert result == CheckResult(Outcome.VERIFIED)
    assert txt.queries == ["_hindama-verificacion.api.hindama.test"]  # never the parent domain


async def test_no_txt_record(txt: FakeTxtResolver) -> None:
    result = await checker(txt).check(VerificationMethod.DNS, base_url="", host=HOST, code=CODE)
    assert result == CheckResult(Outcome.TXT_MISSING)


async def test_txt_records_without_the_code(txt: FakeTxtResolver) -> None:
    txt.records[dns_name(HOST)] = ["hindama-verificacion=viejo", "otro"]
    result = await checker(txt).check(VerificationMethod.DNS, base_url="", host=HOST, code=CODE)
    assert result == CheckResult(Outcome.TXT_MISSING, "hindama-verificacion=viejo; otro")


async def test_the_record_of_the_parent_domain_does_not_count(txt: FakeTxtResolver) -> None:
    txt.records[dns_name("hindama.test")] = [CODE]
    result = await checker(txt).check(VerificationMethod.DNS, base_url="", host=HOST, code=CODE)
    assert result.outcome == Outcome.TXT_MISSING


async def test_a_dns_that_does_not_answer(txt: FakeTxtResolver) -> None:
    txt.failing.add(dns_name(HOST))
    result = await checker(txt).check(VerificationMethod.DNS, base_url="", host=HOST, code=CODE)
    assert result == CheckResult(Outcome.CONNECTION_ERROR)


# ---------------------------------------------------------------- dnspython adapter


def _answer(*texts: str) -> list[dns.rdata.Rdata]:
    return [dns.rdata.from_text("IN", "TXT", text) for text in texts]


async def test_system_resolver_joins_the_strings_of_each_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queries: list[tuple[str, str]] = []

    async def resolve(_: object, name: str, kind: str, **__: object) -> list[dns.rdata.Rdata]:
        queries.append((name, kind))
        return _answer('"hindama-verificacion=" "abc"', '"v=spf1 -all"')

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    records = await SystemTxtResolver().txt("_hindama-verificacion.api.ejemplo.com")
    assert records == ["hindama-verificacion=abc", "v=spf1 -all"]
    assert queries == [("_hindama-verificacion.api.ejemplo.com", "TXT")]


@pytest.mark.parametrize("error", [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer])
async def test_system_resolver_without_records(
    monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    async def resolve(*_: object, **__: object) -> None:
        raise error

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    assert await SystemTxtResolver().txt("_hindama-verificacion.x.test") == []


@pytest.mark.parametrize("error", [dns.exception.Timeout, dns.resolver.NoNameservers])
async def test_system_resolver_failures(
    monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    async def resolve(*_: object, **__: object) -> None:
        raise error

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    with pytest.raises(TxtLookupError):
        await SystemTxtResolver().txt("_hindama-verificacion.x.test")
