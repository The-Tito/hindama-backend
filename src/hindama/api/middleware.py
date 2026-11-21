"""HTTP middleware: request context, authentication, the rate limit and the upload limit.

RequestContextMiddleware is the outermost one: request id, access log and last-resort error
handling. Both are pure ASGI middleware (not BaseHTTPMiddleware) so they also work with streaming
responses such as the SSE progress stream (ADR-006).
"""

import re
import time

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hindama.api.problems import (
    app_error_response,
    internal_error_response,
    problem_response,
    unauthenticated_response,
)
from hindama.core.auth import InvalidTokenError, TokenVerifier
from hindama.core.errors import AppError
from hindama.core.rate_limit import RateLimiter
from hindama.core.request_context import (
    REQUEST_ID_HEADER,
    accept_or_generate,
    set_request_id,
)
from hindama.services.contracts import ContractTooLargeError

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


class RateLimitMiddleware:
    """At most `limit` requests per minute per user (RNF-09): 429 with `Retry-After`.

    It runs right after authentication, so the user is the token's `sub` (never something the
    client chooses) and a request without a session is rejected before it counts.
    """

    def __init__(self, app: ASGIApp, limiter: RateLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        principal = scope.get("state", {}).get("principal") if scope["type"] == "http" else None
        if principal is None:  # a public path
            await self.app(scope, receive, send)
            return
        retry_after = await self.limiter.hit(principal.cognito_sub)
        if retry_after is None:
            await self.app(scope, receive, send)
            return
        log.info("rate_limited", path=scope["path"], retry_after=retry_after)
        response = problem_response(
            429,
            "rate_limit.exceeded",
            "Demasiadas peticiones",
            "Superaste el límite de peticiones por minuto. Espera un momento e intenta de nuevo.",
            headers={"Retry-After": str(retry_after)},
        )
        await response(scope, receive, send)


class UploadLimitMiddleware:
    """Caps the body of the contract upload before anything parses it (RF-22, RNF-07).

    Starlette writes a multipart file to disk while parsing it, so the 5 MB limit must act earlier:
    a declared `Content-Length` over the limit is rejected at once, and otherwise the body is read
    here, counted, and replayed to the app only if it fits. It runs after authentication, so only
    an analyst's request is ever buffered.
    """

    def __init__(self, app: ASGIApp, limit: int, path: re.Pattern[str]) -> None:
        self.app = app
        self.limit = limit
        self.path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or not self.path.fullmatch(scope["path"])
        ):
            await self.app(scope, receive, send)
            return
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > self.limit:
            await app_error_response(ContractTooLargeError())(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":  # the client went away
                return
            body.extend(message.get("body", b""))
            if len(body) > self.limit:
                await app_error_response(ContractTooLargeError())(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
