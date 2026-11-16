"""The contract upload is capped before anything parses it (RF-22, RNF-07)."""

import json
import re
from typing import Any

from starlette.types import Message, Receive, Scope, Send

from hindama.api.middleware import UploadLimitMiddleware

PATH = re.compile(r"/projects/[^/]+/contracts")
LIMIT = 100


class App:
    """Records the body it received."""

    def __init__(self) -> None:
        self.body: bytes | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        self.body = body
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b""})


async def call(
    chunks: list[bytes],
    *,
    path: str = "/projects/1/contracts",
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    disconnect: bool = False,
) -> tuple[App, list[Message]]:
    app = App()
    middleware = UploadLimitMiddleware(app, limit=LIMIT, path=PATH)
    queue: list[Message] = [
        {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
        for i, chunk in enumerate(chunks)
    ]
    if disconnect:
        queue = [{**queue[0], "more_body": True}, {"type": "http.disconnect"}]
    sent: list[Message] = []

    async def receive() -> Message:
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: dict[str, Any] = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
    }
    await middleware(scope, receive, send)
    return app, sent


def problem(sent: list[Message]) -> tuple[int, dict[str, Any]]:
    return sent[0]["status"], json.loads(sent[1]["body"])


async def test_a_body_within_the_limit_reaches_the_app_whole() -> None:
    app, sent = await call([b"a" * 60, b"b" * 40])
    assert app.body == b"a" * 60 + b"b" * 40
    assert sent[0]["status"] == 201


async def test_a_declared_length_over_the_limit_is_rejected_at_once() -> None:
    app, sent = await call([b"x"], headers=[(b"content-length", b"101")])
    status, body = problem(sent)
    assert (status, body["code"]) == (413, "contract.too_large")
    assert app.body is None


async def test_a_body_without_length_is_cut_while_it_arrives() -> None:
    app, sent = await call([b"x" * 60, b"x" * 60, b"x" * 60])
    assert problem(sent)[0] == 413
    assert app.body is None


async def test_a_client_that_goes_away_gets_nothing() -> None:
    app, sent = await call([b"x" * 10], disconnect=True)
    assert (app.body, sent) == (None, [])


async def test_other_requests_are_not_buffered() -> None:
    for path, method in (("/projects/1/contracts", "GET"), ("/projects", "POST")):
        app, sent = await call([b"x" * 500], path=path, method=method)
        assert app.body == b"x" * 500
        assert sent[0]["status"] == 201
