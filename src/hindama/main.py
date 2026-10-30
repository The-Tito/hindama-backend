"""FastAPI application factory.

Run locally with: `uv run uvicorn hindama.main:create_app --factory --no-access-log`
(the access log is written by RequestContextMiddleware, without query strings).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from hindama.api import health
from hindama.api.middleware import RequestContextMiddleware
from hindama.api.problems import register_problem_handlers
from hindama.config import Settings, get_settings
from hindama.core.logging import configure_logging
from hindama.db.session import create_engine, create_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)
    engine = create_engine(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await engine.dispose()

    app = FastAPI(
        title="Hindama API",
        version="0.2.0",
        lifespan=lifespan,
        # The API is private (only Next.js reaches it); the interactive docs are for development.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)

    register_problem_handlers(app)
    app.add_middleware(RequestContextMiddleware)
    app.include_router(health.router)
    return app
