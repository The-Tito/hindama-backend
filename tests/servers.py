"""A local stand-in for the user's API, and scripted DNS answers, for tests that go through
`SafeHttpClient` without the Internet (ADR-008, technical test PT-01).

The server listens on loopback. Tests resolve a fictitious host (`api.hindama.test`, in no DNS) to
it, and relax the address policy for loopback only: everything else is the production policy.
"""

import ipaddress
import socket
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import trustme
import uvicorn
from starlette.types import ASGIApp

from hindama.core.destinations import IPAddress, UnresolvedHostError, is_blocked

HOST = "api.hindama.test"
LOOPBACK = "127.0.0.1"


class LocalServer:
    """Serves `app` on a free loopback port, in a thread. HTTPS when given a certificate."""

    def __init__(self, app: ASGIApp, **ssl_files: str) -> None:
        self._socket = socket.socket()
        self._socket.bind((LOOPBACK, 0))
        self.port: int = self._socket.getsockname()[1]
        config = uvicorn.Config(app, log_level="warning", lifespan="off", **ssl_files)  # type: ignore[arg-type]
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


@contextmanager
def https_server(app: ASGIApp, ca: trustme.CA, directory: Path) -> Iterator[LocalServer]:
    """A server with a certificate for `HOST`, signed by the test CA."""
    pem = directory / "server.pem"
    ca.issue_cert(HOST).private_key_and_cert_chain_pem.write_to_path(str(pem))
    with LocalServer(app, ssl_certfile=str(pem), ssl_keyfile=str(pem)) as server:
        yield server


def trusting(ca: trustme.CA) -> ssl.SSLContext:
    context = ssl.create_default_context()
    ca.configure_trust(context)
    return context


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
