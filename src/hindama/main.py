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
    admin,
    contracts,
    findings,
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
    RateLimitMiddleware,
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
from hindama.core.rate_limit import NoRateLimiter, RateLimiter, RedisRateLimiter
from hindama.core.run_events import RedisRunEvents, RunEvents, UnconfiguredRunEvents
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
    run_events: RunEvents | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    """`verifier` and `profiles` are injected only by tests, with a fake User Pool, `resolver`
    with a fake DNS, `ownership_checker` with a local server or scripted results,
    `identity_prober` with one that may reach a local server, and `run_queue`, `run_events` and
    `rate_limiter` with ones in memory."""
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

    redis_url = settings.redis_url
    if run_queue is None:
        run_queue = (
            UnconfiguredRunQueue()
            if redis_url is None
            else SaqRunQueue.from_url(redis_url.get_secret_value())
        )
    if run_events is None:  # the progress of runs (ADR-006), in the same Redis as the queue
        run_events = (
            UnconfiguredRunEvents()
            if redis_url is None
            else RedisRunEvents.from_url(redis_url.get_secret_value())
        )

    if rate_limiter is None:  # RNF-09, in the same Redis
        rate_limiter = (
            NoRateLimiter()
            if redis_url is None
            else RedisRateLimiter.from_url(
                redis_url.get_secret_value(), settings.rate_limit_per_minute
            )
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await run_queue.close()
        await run_events.close()
        await rate_limiter.close()
        await jwks_http.aclose()
        await cognito_http.aclose()
        await engine.dispose()

    app = FastAPI(
        title="Hindama API",
        version="0.12.0",
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
    # HMAC keys of the audit log (ADR-015): the log keeps a host's HMAC, never the host (RF-83).
    app.state.host_hasher = settings.host_hasher()
    app.state.identity_prober = identity_prober
    app.state.run_queue = run_queue
    app.state.run_events = run_events

    register_problem_handlers(app)
    # The last one added is the outermost: request context wraps authentication.
    public_paths = {"/health"} if settings.is_production else {"/health", "/docs", "/openapi.json"}
    # Innermost: the upload is buffered only once the caller is authenticated.
    app.add_middleware(UploadLimitMiddleware, limit=UPLOAD_BODY_LIMIT, path=CONTRACT_UPLOAD_PATH)
    # Right after authentication: it counts per user (RNF-09).
    app.add_middleware(RateLimitMiddleware, limiter=rate_limiter)
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
    app.include_router(findings.router)
    app.include_router(admin.router)
    return app
