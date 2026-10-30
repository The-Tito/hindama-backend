"""Outermost middleware: request id, access log and last-resort error handling.

It is a pure ASGI middleware (not BaseHTTPMiddleware) so it also works with streaming responses
such as the SSE progress stream (ADR-006).
"""

import time

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hindama.api.problems import internal_error_response
from hindama.core.request_context import (
    REQUEST_ID_HEADER,
    accept_or_generate,
    set_request_id,
)

log = structlog.get_logger("hindama.http")


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = accept_or_generate(Headers(scope=scope).get(REQUEST_ID_HEADER))
        set_request_id(request_id)
        started = time.perf_counter()
        status_code = 500
        response_started = False

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        except Exception:
            # Logged with its (masked) traceback; never sent to the client (RNF-07).
            log.exception("unhandled_error", method=scope["method"], path=scope["path"])
            if response_started:
                raise
            await internal_error_response()(scope, receive, send_with_request_id)
        finally:
            # Only method, path and status: query strings are not logged (convenciones.md, sec. 11).
            log.info(
                "request",
                method=scope["method"],
                path=scope["path"],
                status=status_code,
                duration_ms=round((time.perf_counter() - started) * 1000, 1),
            )
            set_request_id(None)
