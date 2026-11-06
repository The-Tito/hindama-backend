"""The only HTTP client for destinations the user controls (ADR-008; RF-11, RF-20, RF-22, RF-50).

Ownership verification, contract import by URL and every request of the scanner go through
`SafeHttpClient`. On each request, and again on each redirect, it:

1. accepts only `http`/`https`, without credentials in the URL, and only the host the client is
   bound to (the project's verified host, never its parent domain or a sibling);
2. resolves A and AAAA records and refuses if ANY address is private, loopback, link local,
   metadata, reserved or one of Hindama's own (`destinations.is_blocked`);
3. pins the connection to the validated address: `PinnedNetworkBackend` opens the socket to that IP
   and never resolves again, while TLS still sends the original name (SNI) and validates the
   certificate against it. A DNS answer that changes between validation and connection (DNS
   rebinding) cannot reach the network;
4. follows at most 3 redirects, each one validated as above;
5. applies connect and read timeouts, and reads the body as a stream, cutting it at a maximum size.

Why a network backend and not "rewrite the URL to the IP and set `sni_hostname`": httpcore pools
connections by origin. With the URL rewritten, two hosts sharing an IP (common behind a CDN) shared
one TLS connection and the second host's certificate was never checked (technical test PT-01,
hindama-docs/01-arquitectura/pruebas-tecnicas.md). Here the origin keeps the host name.

`PinnedTransport` plugs the backend into httpx through public interfaces of both libraries, instead
of replacing the private pool of `httpx.AsyncHTTPTransport`.
"""

import ipaddress
import ssl
from collections.abc import AsyncIterable, AsyncIterator, Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpcore
import httpx
import structlog

from hindama.core.destinations import (
    ALLOWED_SCHEMES,
    IPAddress,
    Resolver,
    UnresolvedHostError,
    is_blocked,
)

log = structlog.get_logger("hindama.safe_http")

USER_AGENT = "Hindama-Scanner/1.0"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True, slots=True)
class Limits:
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    max_redirects: int = 3
    max_response_bytes: int = 10 * 1024 * 1024


class BlockReason(StrEnum):
    INVALID_URL = "invalid_url"  # credentials in the URL or no host
    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    HOST_MISMATCH = "host_mismatch"
    UNRESOLVED = "unresolved"
    ADDRESS_NOT_ALLOWED = "address_not_allowed"
    TOO_MANY_REDIRECTS = "too_many_redirects"


class DestinationBlockedError(Exception):
    """The request never left: the destination is not allowed (logged; RF-81 audits it later)."""

    def __init__(self, reason: BlockReason, host: str) -> None:
        super().__init__(f"{reason.value}: {host}")
        self.reason = reason
        self.host = host


class ResponseTooLargeError(Exception):
    def __init__(self, limit: int) -> None:
        super().__init__(f"response larger than {limit} bytes")
        self.limit = limit


# ---------------------------------------------------------------- transport


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Opens TCP connections only to the address validated for each host; never resolves DNS."""

    def __init__(self) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._pins: dict[str, str] = {}

    def pin(self, host: str, address: IPAddress) -> None:
        self._pins[host] = str(address)

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - signature of httpcore's interface
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        address = self._pins.get(host)
        if address is None:
            raise httpcore.ConnectError(f"no validated address for {host}")
        return await self._inner.connect_tcp(
            address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - signature of httpcore's interface
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


# Most specific first: the first match wins.
_EXCEPTIONS: tuple[tuple[type[Exception], type[httpx.TransportError]], ...] = (
    (httpcore.ConnectTimeout, httpx.ConnectTimeout),
    (httpcore.ReadTimeout, httpx.ReadTimeout),
    (httpcore.WriteTimeout, httpx.WriteTimeout),
    (httpcore.PoolTimeout, httpx.PoolTimeout),
    (httpcore.TimeoutException, httpx.TimeoutException),
    (httpcore.ConnectError, httpx.ConnectError),
    (httpcore.ReadError, httpx.ReadError),
    (httpcore.WriteError, httpx.WriteError),
    (httpcore.NetworkError, httpx.NetworkError),
    (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
    (httpcore.LocalProtocolError, httpx.LocalProtocolError),
    (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
    (httpcore.ProtocolError, httpx.ProtocolError),
)


@contextmanager
def _httpx_errors(request: httpx.Request) -> Iterator[None]:
    """httpcore errors as the httpx errors every caller already handles."""
    try:
        yield
    except Exception as error:
        for source, target in _EXCEPTIONS:
            if isinstance(error, source):
                raise target(str(error), request=request) from error
        raise


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: AsyncIterable[bytes], request: httpx.Request) -> None:
        self._stream = stream
        self._request = request

    async def __aiter__(self) -> AsyncIterator[bytes]:
        with _httpx_errors(self._request):
            async for part in self._stream:
                yield part

    async def aclose(self) -> None:
        close = getattr(self._stream, "aclose", None)
        if close is not None:
            await close()


class PinnedTransport(httpx.AsyncBaseTransport):
    """httpx transport over an httpcore pool that uses `PinnedNetworkBackend`. HTTP/1.1 only."""

    def __init__(self, backend: PinnedNetworkBackend, ssl_context: ssl.SSLContext) -> None:
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            network_backend=backend,
            http1=True,
            http2=False,
            retries=0,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.AsyncByteStream):  # pragma: no cover
            raise TypeError("an async request body is required")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with _httpx_errors(request):
            response = await self._pool.handle_async_request(core_request)
        if not isinstance(response.stream, AsyncIterable):  # pragma: no cover
            raise TypeError("an async response body is required")
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream, request),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


# ---------------------------------------------------------------- client


@dataclass(frozen=True, slots=True)
class SafeResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes
    url: str  # the final URL, after redirects: what evidence shows (never the IP)
    address: IPAddress  # where the last request actually connected
    redirects: tuple[str, ...]


class SafeHttpClient:
    """A client bound to ONE host (ADR-008 step 1): one per project, or per imported URL.

    Use it as an async context manager. Raises `DestinationBlockedError` before any connection to a
    destination that is not allowed, `ResponseTooLargeError`, and httpx's `TimeoutException` and
    `TransportError` (a certificate that does not match is an `httpx.ConnectError`).
    """

    def __init__(
        self,
        host: str,
        *,
        resolver: Resolver,
        own_addresses: Iterable[IPAddress] = (),
        limits: Limits | None = None,
        user_agent: str = USER_AGENT,
        ssl_context: ssl.SSLContext | None = None,
        address_policy: Callable[[IPAddress], bool] | None = None,
    ) -> None:
        self.host = host.lower()
        self.limits = limits or Limits()
        self._resolver = resolver
        own = tuple(own_addresses)
        # Tests allow loopback to reach their local server; production uses `is_blocked` as is.
        self._blocked = address_policy or (lambda address: is_blocked(address, own))
        self._backend = PinnedNetworkBackend()
        self._client = httpx.AsyncClient(
            transport=PinnedTransport(self._backend, ssl_context or httpx.create_ssl_context()),
            timeout=httpx.Timeout(self.limits.read_timeout, connect=self.limits.connect_timeout),
            follow_redirects=False,
            # Proxies from the environment (HTTPS_PROXY, ...) would connect instead of the pinned
            # address and resolve the name themselves.
            trust_env=False,
            headers={"User-Agent": user_agent},
        )

    async def __aenter__(self) -> "SafeHttpClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, **kwargs: Any) -> SafeResponse:
        return await self.request("GET", url, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
        follow_redirects: bool = True,
        max_response_bytes: int | None = None,
    ) -> SafeResponse:
        limit = max_response_bytes or self.limits.max_response_bytes
        current = httpx.URL(url)
        redirects: list[str] = []
        for _ in range(self.limits.max_redirects + 1):
            address = await self._validate(current)
            self._backend.pin(self._host_of(current), address)
            request = self._client.build_request(method, current, headers=headers, content=content)
            response = await self._client.send(request, stream=True)
            try:
                location = response.headers.get("location")
                if follow_redirects and response.status_code in REDIRECT_STATUSES and location:
                    current = current.join(location)
                    redirects.append(str(current))
                    if response.status_code == 303 or (
                        response.status_code in (301, 302) and method == "POST"
                    ):
                        method, content = "GET", None
                    continue
                body = await self._read(response, limit)
            finally:
                await response.aclose()
            return SafeResponse(
                status_code=response.status_code,
                headers=response.headers,
                content=body,
                url=str(current),
                address=address,
                redirects=tuple(redirects),
            )
        raise self._blocked_error(BlockReason.TOO_MANY_REDIRECTS, self._host_of(current))

    # ------------------------------------------------------------ steps

    @staticmethod
    def _host_of(url: httpx.URL) -> str:
        return url.raw_host.decode("ascii").lower()

    async def _validate(self, url: httpx.URL) -> IPAddress:
        """Steps 1 and 2. Returns the address to pin (IPv4 first: the backend leaves by IPv4)."""
        host = self._host_of(url)
        if url.scheme not in ALLOWED_SCHEMES:
            raise self._blocked_error(BlockReason.SCHEME_NOT_ALLOWED, host)
        if not host or url.userinfo:
            raise self._blocked_error(BlockReason.INVALID_URL, host)
        if host != self.host:
            raise self._blocked_error(BlockReason.HOST_MISMATCH, host)
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                addresses = await self._resolver.resolve(host)
            except UnresolvedHostError:
                raise self._blocked_error(BlockReason.UNRESOLVED, host) from None
        if not addresses:
            raise self._blocked_error(BlockReason.UNRESOLVED, host)
        if any(self._blocked(address) for address in addresses):
            raise self._blocked_error(BlockReason.ADDRESS_NOT_ALLOWED, host)
        return min(addresses, key=lambda address: address.version)

    @staticmethod
    async def _read(response: httpx.Response, limit: int) -> bytes:
        """Step 5. Counts decoded bytes, so a compressed bomb is cut too."""
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            raise ResponseTooLargeError(limit)
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > limit:
                raise ResponseTooLargeError(limit)
        return bytes(body)

    def _blocked_error(self, reason: BlockReason, host: str) -> DestinationBlockedError:
        log.warning("destination_blocked", reason=reason.value, host=host, bound_host=self.host)
        return DestinationBlockedError(reason, host)
