"""HTTP middleware: request context and authentication.

RequestContextMiddleware is the outermost one: request id, access log and last-resort error
handling. Both are pure ASGI middleware (not BaseHTTPMiddleware) so they also work with streaming
responses such as the SSE progress stream (ADR-006).
"""

import time

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hindama.api.problems import (
    app_error_response,
    internal_error_response,
    unauthenticated_response,
)
from hindama.core.auth import InvalidTokenError, TokenVerifier
from hindama.core.errors import AppError
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


class AuthenticationMiddleware:
    """Rejects every request without a valid Cognito access token (RF-07).

    It runs before routing, so without a session nothing else exists: a missing route also answers
    401 instead of 404 (convenciones.md, section 3). The caller is left in
    `request.state.principal`.
    """

    def __init__(self, app: ASGIApp, verifier: TokenVerifier, public_paths: frozenset[str]) -> None:
        self.app = app
        self.verifier = verifier
        self.public_paths = public_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.public_paths:
            await self.app(scope, receive, send)
            return

        authorization = Headers(scope=scope).get("authorization")
        if not authorization:
            await unauthenticated_response("auth.required")(scope, receive, send)
            return
        scheme, _, token = authorization.partition(" ")
        try:
            if scheme.lower() != "bearer" or not token.strip():
                raise InvalidTokenError("not a bearer token")
            principal = await self.verifier.verify(token.strip())
        except InvalidTokenError as error:
            log.info("invalid_token", reason=str(error))  # the reason only, never the token
            await unauthenticated_response("auth.invalid_token")(scope, receive, send)
            return
        except AppError as error:  # the keys of Cognito are unavailable
            await app_error_response(error)(scope, receive, send)
            return

        scope.setdefault("state", {})["principal"] = principal
        await self.app(scope, receive, send)
