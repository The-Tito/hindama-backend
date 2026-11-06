"""The SSRF guard (ADR-008): the scenarios of technical test PT-01, without the Internet.

A local TLS server (certificate for `api.hindama.test`, signed by a test CA) and scripted resolvers
stand in for the user's API and DNS. `api.hindama.test` does not exist in any DNS: a request only
reaches the server through the address the client validated and pinned.
"""

import asyncio
import ipaddress
import socket
import ssl
import threading
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpcore
import httpx
import pytest
import structlog
import trustme
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Route

from hindama.core.destinations import IPAddress, UnresolvedHostError, is_blocked
from hindama.core.safe_http import (
    USER_AGENT,
    BlockReason,
    DestinationBlockedError,
    Limits,
    PinnedNetworkBackend,
    ResponseTooLargeError,
    SafeHttpClient,
)

HOST = "api.hindama.test"
LOOPBACK = "127.0.0.1"


# ---------------------------------------------------------------- the "user's API"


async def ok(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "host": request.headers.get("host"),
            "user_agent": request.headers.get("user-agent"),
            "method": request.method,
            "length": len(await request.body()),
        }
    )


async def redirect(request: Request) -> RedirectResponse:
    status = int(request.query_params.get("status", "302"))
    return RedirectResponse(request.query_params["to"], status_code=status)


async def chain(request: Request) -> Response:
    hops = int(request.path_params["hops"])
    if hops > 0:
        return RedirectResponse(f"/chain/{hops - 1}")
    return JSONResponse({"done": True})


async def slow(_: Request) -> Response:
    await asyncio.sleep(3)
    return Response("tarde")


async def big(request: Request) -> Response:
    return Response(b"x" * int(request.query_params["size"]))


async def chunked(request: Request) -> StreamingResponse:
    size = int(request.query_params["size"])

    async def body() -> AsyncIterator[bytes]:
        for _ in range(size // 256):
            yield b"x" * 256

    return StreamingResponse(body())  # no Content-Length


APP = Starlette(
    routes=[
        Route("/ok", ok, methods=["GET", "POST"]),
        Route("/redirect", redirect, methods=["GET", "POST"]),
        Route("/chain/{hops:int}", chain),
        Route("/slow", slow),
        Route("/big", big),
        Route("/chunked", chunked),
    ]
)


class LocalServer:
    def __init__(self, **ssl_files: str) -> None:
        self._socket = socket.socket()
        self._socket.bind((LOOPBACK, 0))
        self.port: int = self._socket.getsockname()[1]
        config = uvicorn.Config(APP, log_level="warning", lifespan="off", **ssl_files)  # type: ignore[arg-type]
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [self._socket]}, daemon=True
        )

    def __enter__(self) -> "LocalServer":
        self._thread.start()
        for _ in range(200):
            if self._server.started:
                return self
            threading.Event().wait(0.01)
        raise RuntimeError("the local server did not start")

    def __exit__(self, *_: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="module")
def https_server(ca: trustme.CA, tmp_path_factory: pytest.TempPathFactory) -> Iterator[LocalServer]:
    pem = Path(tmp_path_factory.mktemp("tls")) / "server.pem"
    ca.issue_cert(HOST).private_key_and_cert_chain_pem.write_to_path(str(pem))
    with LocalServer(ssl_certfile=str(pem), ssl_keyfile=str(pem)) as server:
        yield server


@pytest.fixture(scope="module")
def http_server() -> Iterator[LocalServer]:
    with LocalServer() as server:
        yield server


@pytest.fixture
def trusted(ca: trustme.CA) -> ssl.SSLContext:
    context = ssl.create_default_context()
    ca.configure_trust(context)
    return context


# ---------------------------------------------------------------- resolvers and policy


class ScriptedResolver:
    """Answers in order (the last answer repeats) and records every query."""

    def __init__(self, *answers: list[str]) -> None:
        self.answers = answers
        self.queries: list[str] = []

    async def resolve(self, host: str) -> list[IPAddress]:
        self.queries.append(host)
        answer = self.answers[min(len(self.queries), len(self.answers)) - 1]
        return [ipaddress.ip_address(a) for a in answer]


class UnresolvedResolver:
    async def resolve(self, host: str) -> list[IPAddress]:
        raise UnresolvedHostError(host)


def allow_loopback(address: IPAddress) -> bool:
    """Production policy except loopback, where the local server listens."""
    return is_blocked(address) and not address.is_loopback


def client(
    host: str = HOST,
    resolver: object | None = None,
    *,
    ssl_context: ssl.SSLContext | None = None,
    limits: Limits | None = None,
    policy: bool = True,
) -> SafeHttpClient:
    return SafeHttpClient(
        host,
        resolver=resolver or ScriptedResolver([LOOPBACK]),  # type: ignore[arg-type]
        ssl_context=ssl_context,
        limits=limits,
        address_policy=allow_loopback if policy else None,
    )


def https(server: LocalServer, path: str, host: str = HOST) -> str:
    return f"https://{host}:{server.port}{path}"


# ---------------------------------------------------------------- TLS with the pinned address


async def test_https_reaches_the_pinned_address_with_the_original_name(
    https_server: LocalServer, trusted: ssl.SSLContext
) -> None:
    resolver = ScriptedResolver([LOOPBACK])
    async with client(resolver=resolver, ssl_context=trusted) as safe:
        response = await safe.get(https(https_server, "/ok"))

    assert response.status_code == 200
    body = httpx.Response(200, content=response.content).json()
    assert body["host"] == f"{HOST}:{https_server.port}"  # Host header kept
    assert body["user_agent"] == USER_AGENT
    assert response.url == https(https_server, "/ok")  # evidence shows the name, never the IP
    assert response.address == ipaddress.ip_address(LOOPBACK)
    assert resolver.queries == [HOST]  # one resolution, through our resolver only


async def test_a_certificate_for_another_name_is_rejected(
    https_server: LocalServer, trusted: ssl.SSLContext
) -> None:
    # The pinned address serves a valid certificate, but for api.hindama.test.
    async with client("ajeno.hindama.test", ssl_context=trusted) as safe:
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            await safe.get(https(https_server, "/ok", host="ajeno.hindama.test"))


async def test_a_certificate_from_an_untrusted_authority_is_rejected(
    https_server: LocalServer,
) -> None:
    async with client() as safe:  # system trust store: the test CA is not in it
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            await safe.get(https(https_server, "/ok"))


async def test_proxies_from_the_environment_are_ignored(
    https_server: LocalServer, trusted: ssl.SSLContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")  # nothing listens there

    async with client(ssl_context=trusted) as safe:
        response = await safe.get(https(https_server, "/ok"))

    assert response.status_code == 200


# ---------------------------------------------------------------- destinations


@pytest.mark.parametrize(
    "answer",
    [
        ["127.0.0.1"],
        ["169.254.169.254"],  # cloud metadata
        ["10.0.0.7"],
        ["::1"],
        ["fd00:ec2::254"],
        ["::ffff:169.254.169.254"],
        ["93.184.215.14", "10.0.0.7"],  # ANY blocked address blocks the host
    ],
)
async def test_blocked_addresses_never_get_a_connection(answer: list[str]) -> None:
    async with client(resolver=ScriptedResolver(answer), policy=False) as safe:
        with pytest.raises(DestinationBlockedError) as blocked:
            await safe.get(f"https://{HOST}/ok")

    assert blocked.value.reason is BlockReason.ADDRESS_NOT_ALLOWED


async def test_hindama_own_addresses_are_blocked() -> None:
    own = ipaddress.ip_address("93.184.215.14")
    safe = SafeHttpClient(HOST, resolver=ScriptedResolver([str(own)]), own_addresses=[own])
    async with safe:
        with pytest.raises(DestinationBlockedError) as blocked:
            await safe.get(f"https://{HOST}/ok")

    assert blocked.value.reason is BlockReason.ADDRESS_NOT_ALLOWED


async def test_ip_literals_are_checked_without_dns(http_server: LocalServer) -> None:
    resolver = ScriptedResolver([LOOPBACK])
    async with client("169.254.169.254", resolver, policy=False) as metadata:
        with pytest.raises(DestinationBlockedError) as blocked:
            await metadata.get("http://169.254.169.254/latest/meta-data/")
    async with client(LOOPBACK, resolver) as local:
        allowed = await local.get(f"http://{LOOPBACK}:{http_server.port}/ok")

    assert blocked.value.reason is BlockReason.ADDRESS_NOT_ALLOWED
    assert allowed.status_code == 200
    assert resolver.queries == []


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://otro.hindama.test/ok", BlockReason.HOST_MISMATCH),
        ("https://hindama.test/ok", BlockReason.HOST_MISMATCH),  # parent domain
        ("https://sub.api.hindama.test/ok", BlockReason.HOST_MISMATCH),
        (f"ftp://{HOST}/ok", BlockReason.SCHEME_NOT_ALLOWED),
        ("file:///etc/passwd", BlockReason.SCHEME_NOT_ALLOWED),
        (f"https://usuario:clave@{HOST}/ok", BlockReason.INVALID_URL),
    ],
)
async def test_only_the_bound_host_over_http_or_https(url: str, reason: BlockReason) -> None:
    resolver = ScriptedResolver([LOOPBACK])
    async with client(resolver=resolver) as safe:
        with pytest.raises(DestinationBlockedError) as blocked:
            await safe.get(url)

    assert blocked.value.reason is reason
    assert resolver.queries == []


async def test_a_host_that_does_not_resolve_is_blocked() -> None:
    async with client(resolver=UnresolvedResolver()) as safe:
        with pytest.raises(DestinationBlockedError) as blocked:
            await safe.get(f"https://{HOST}/ok")

    assert blocked.value.reason is BlockReason.UNRESOLVED


async def test_every_block_is_logged() -> None:
    with structlog.testing.capture_logs() as logs:
        async with client() as safe:
            with pytest.raises(DestinationBlockedError):
                await safe.get("https://otro.hindama.test/ok")

    assert {"event": "destination_blocked", "reason": "host_mismatch"}.items() <= logs[0].items()


# ---------------------------------------------------------------- DNS rebinding


async def test_dns_rebinding_cannot_reach_the_network(
    https_server: LocalServer, trusted: ssl.SSLContext
) -> None:
    # First answer: an allowed address. Every later one: a private address.
    resolver = ScriptedResolver([LOOPBACK], ["10.0.0.7"])
    async with client(resolver=resolver, ssl_context=trusted) as safe:
        response = await safe.get(https(https_server, "/ok"))

    assert response.status_code == 200
    assert response.address == ipaddress.ip_address(LOOPBACK)
    assert resolver.queries == [HOST]  # resolved once: the connection never asked again


async def test_a_redirect_is_resolved_and_validated_again(
    https_server: LocalServer, trusted: ssl.SSLContext
) -> None:
    resolver = ScriptedResolver([LOOPBACK], ["169.254.169.254"])
    async with client(resolver=resolver, ssl_context=trusted) as safe:
        with pytest.raises(DestinationBlockedError) as blocked:
            await safe.get(https(https_server, "/chain/1"))

    assert blocked.value.reason is BlockReason.ADDRESS_NOT_ALLOWED
    assert resolver.queries == [HOST, HOST]


# ---------------------------------------------------------------- redirects


async def test_up_to_three_redirects_on_the_same_host(
    https_server: LocalServer, trusted: ssl.SSLContext
) -> None:
    async with client(ssl_context=trusted) as safe:
        response = await safe.get(https(https_server, "/chain/3"))
        with pytest.raises(DestinationBlockedError) as blocked:
            await safe.get(https(https_server, "/chain/4"))

    assert response.status_code == 200
    assert response.redirects == tuple(https(https_server, f"/chain/{n}") for n in (2, 1, 0))
    assert response.url == https(https_server, "/chain/0")
    assert blocked.value.reason is BlockReason.TOO_MANY_REDIRECTS


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com/",
        "http://169.254.169.254/latest/meta-data/",
        f"https://{LOOPBACK}/ok",
    ],
)
async def test_a_redirect_off_the_host_is_blocked(
    https_server: LocalServer, trusted: ssl.SSLContext, target: str
) -> None:
    async with client(ssl_context=trusted) as safe:
        with pytest.raises(DestinationBlockedError) as blocked:
            await safe.get(https(https_server, f"/redirect?to={target}"))

    assert blocked.value.reason is BlockReason.HOST_MISMATCH


async def test_redirects_can_be_left_to_the_caller(
    https_server: LocalServer, trusted: ssl.SSLContext
) -> None:
    async with client(ssl_context=trusted) as safe:
        response = await safe.get(https(https_server, "/chain/1"), follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == "/chain/0"


@pytest.mark.parametrize(("status", "method", "length"), [(303, "GET", 0), (307, "POST", 5)])
async def test_redirect_method_rules(
    https_server: LocalServer, trusted: ssl.SSLContext, status: int, method: str, length: int
) -> None:
    async with client(ssl_context=trusted) as safe:
        response = await safe.request(
            "POST", https(https_server, f"/redirect?to=/ok&status={status}"), content=b"datos"
        )

    body = httpx.Response(200, content=response.content).json()
    assert (body["method"], body["length"]) == (method, length)


# ---------------------------------------------------------------- timeouts and size


async def test_a_response_that_never_ends_times_out(
    https_server: LocalServer, trusted: ssl.SSLContext
) -> None:
    async with client(ssl_context=trusted, limits=Limits(read_timeout=0.3)) as safe:
        with pytest.raises(httpx.ReadTimeout):
            await safe.get(https(https_server, "/slow"))


async def test_a_closed_port_is_a_connect_error(trusted: ssl.SSLContext) -> None:
    unused = socket.socket()
    unused.bind((LOOPBACK, 0))
    port = unused.getsockname()[1]
    unused.close()

    async with client(ssl_context=trusted) as safe:
        with pytest.raises(httpx.ConnectError):
            await safe.get(f"https://{HOST}:{port}/ok")


@pytest.mark.parametrize("path", ["/big?size=2048", "/chunked?size=2048"])
async def test_a_large_response_is_cut(
    https_server: LocalServer, trusted: ssl.SSLContext, path: str
) -> None:
    async with client(ssl_context=trusted) as safe:
        exact = await safe.get(https(https_server, path), max_response_bytes=2048)
        with pytest.raises(ResponseTooLargeError):
            await safe.get(https(https_server, path), max_response_bytes=1024)

    assert len(exact.content) == 2048


# ---------------------------------------------------------------- network backend


async def test_the_backend_never_connects_without_a_validated_address() -> None:
    backend = PinnedNetworkBackend()

    with pytest.raises(httpcore.ConnectError, match="no validated address"):
        await backend.connect_tcp(HOST, 443)
    with pytest.raises(httpcore.ConnectError, match="unix sockets"):
        await backend.connect_unix_socket("/var/run/docker.sock")
