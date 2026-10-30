"""FastAPI application factory.

Run locally with: `uv run uvicorn hindama.main:create_app --factory --no-access-log`
(the access log is written by RequestContextMiddleware, without query strings).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from hindama.api import health
from hindama.api.middleware import AuthenticationMiddleware, RequestContextMiddleware
from hindama.api.openapi import install_openapi
from hindama.api.problems import register_problem_handlers
from hindama.config import Settings, get_settings
from hindama.core.auth import TokenVerifier
from hindama.core.logging import configure_logging
from hindama.db.session import create_engine, create_session_factory


def create_app(settings: Settings | None = None, verifier: TokenVerifier | None = None) -> FastAPI:
    """`verifier` is injected only by tests, with their own signing keys."""
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    engine = create_engine(settings)
    # Only for the Cognito keys. Short timeout, and no redirects: the URL is fixed by configuration.
    jwks_http = httpx.AsyncClient(timeout=5.0, follow_redirects=False)
    verifier = verifier or TokenVerifier(
        issuer=settings.cognito_issuer,
        client_id=settings.cognito_client_id,
        admin_group=settings.cognito_admin_group,
        jwks_url=settings.cognito_jwks_url,
        http=jwks_http,
        cache_seconds=settings.jwks_cache_seconds,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await jwks_http.aclose()
        await engine.dispose()

    app = FastAPI(
        title="Hindama API",
        version="0.2.0",
        lifespan=lifespan,
        # The API is private (only Next.js reaches it); the interactive docs are for development.
        docs_url=None if settings.is_production else "/docs",
        openapi_url=None if settings.is_production else "/openapi.json",
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)

    register_problem_handlers(app)
    # The last one added is the outermost: request context wraps authentication.
    public_paths = {"/health"} if settings.is_production else {"/health", "/docs", "/openapi.json"}
    app.add_middleware(
        AuthenticationMiddleware, verifier=verifier, public_paths=frozenset(public_paths)
    )
    app.add_middleware(RequestContextMiddleware)
    install_openapi(app, frozenset(public_paths))
    app.include_router(health.router)
    return app
