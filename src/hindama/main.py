"""FastAPI application factory.

Run locally with: `uv run uvicorn hindama.main:create_app --factory --no-access-log`
(the access log is written by RequestContextMiddleware, without query strings).
"""

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from hindama.api import (
    accounts,
    contracts,
    health,
    identities,
    policy,
    projects,
    resources,
    runs,
    verification,
)
from hindama.api.middleware import (
    AuthenticationMiddleware,
    RequestContextMiddleware,
    UploadLimitMiddleware,
)
from hindama.api.openapi import install_openapi
from hindama.api.problems import register_problem_handlers
from hindama.config import Settings, get_settings
from hindama.core.auth import TokenVerifier
from hindama.core.cognito import ProfileClient
from hindama.core.destinations import Resolver, SystemResolver
from hindama.core.identity_probe import IdentityProber
from hindama.core.logging import configure_logging
from hindama.core.ownership import NetworkOwnershipChecker, OwnershipChecker, SystemTxtResolver
from hindama.core.run_queue import RunQueue, SaqRunQueue, UnconfiguredRunQueue
from hindama.db.session import create_engine, create_session_factory
from hindama.models.base import MAX_CONTRACT_BYTES

# The 5 MB of the document plus room for the multipart envelope and the other field (RF-22).
UPLOAD_BODY_LIMIT = MAX_CONTRACT_BYTES + 64 * 1024
CONTRACT_UPLOAD_PATH = re.compile(r"/projects/[^/]+/contracts")


def create_app(
    settings: Settings | None = None,
    verifier: TokenVerifier | None = None,
    profiles: ProfileClient | None = None,
    resolver: Resolver | None = None,
    ownership_checker: OwnershipChecker | None = None,
    identity_prober: IdentityProber | None = None,
    run_queue: RunQueue | None = None,
) -> FastAPI:
    """`verifier` and `profiles` are injected only by tests, with a fake User Pool, `resolver`
    with a fake DNS, `ownership_checker` with a local server or scripted results,
    `identity_prober` with one that may reach a local server, and `run_queue` with one in memory."""
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
    # GetUser, with the caller's access token. Same rules: fixed URL, short timeout, no redirects.
    cognito_http = httpx.AsyncClient(timeout=5.0, follow_redirects=False)
    profiles = profiles or ProfileClient(endpoint=settings.cognito_idp_endpoint, http=cognito_http)

    if run_queue is None:
        redis_url = settings.redis_url
        run_queue = (
            UnconfiguredRunQueue()
            if redis_url is None
            else SaqRunQueue.from_url(redis_url.get_secret_value())
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await run_queue.close()
        await jwks_http.aclose()
        await cognito_http.aclose()
        await engine.dispose()

    app = FastAPI(
        title="Hindama API",
        version="0.4.0",
        lifespan=lifespan,
        # The API is private (only Next.js reaches it); the interactive docs are for development.
        docs_url=None if settings.is_production else "/docs",
        openapi_url=None if settings.is_production else "/openapi.json",
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    app.state.profiles = profiles
    app.state.resolver = resolver or SystemResolver()
    app.state.ownership_checker = ownership_checker or NetworkOwnershipChecker(
        resolver=app.state.resolver,
        txt_resolver=SystemTxtResolver(),
        own_addresses=settings.own_ip_addresses,
    )
    # AES-256-GCM keys of the identities' credentials (ADR-007): read once, kept only in memory.
    app.state.credential_cipher = settings.credential_cipher()
    app.state.identity_prober = identity_prober
    app.state.run_queue = run_queue

    register_problem_handlers(app)
    # The last one added is the outermost: request context wraps authentication.
    public_paths = {"/health"} if settings.is_production else {"/health", "/docs", "/openapi.json"}
    # Innermost: the upload is buffered only once the caller is authenticated.
    app.add_middleware(UploadLimitMiddleware, limit=UPLOAD_BODY_LIMIT, path=CONTRACT_UPLOAD_PATH)
    app.add_middleware(
        AuthenticationMiddleware, verifier=verifier, public_paths=frozenset(public_paths)
    )
    app.add_middleware(RequestContextMiddleware)
    install_openapi(app, frozenset(public_paths))
    app.include_router(health.router)
    app.include_router(accounts.router)
    app.include_router(projects.router)
    app.include_router(verification.router)
    app.include_router(contracts.router)
    app.include_router(identities.router)
    app.include_router(resources.router)
    app.include_router(policy.router)
    app.include_router(runs.router)
    return app
