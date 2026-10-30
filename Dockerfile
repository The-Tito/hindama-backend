# syntax=docker/dockerfile:1.7
# Production image of the API (and, later, of the scanner: same image, different command).
# Built for linux/arm64 (Graviton, ADR-002) and also works on amd64.

# ---------------------------------------------------------------- build
FROM python:3.12-slim-bookworm AS build
# uv pinned to the same version used in development.
COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies first, in their own layer: they change less often than the code.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# Unprivileged user with a fixed uid; the image has no shell tools beyond the base.
RUN groupadd --system --gid 10001 hindama \
 && useradd --system --uid 10001 --gid hindama --no-create-home --shell /usr/sbin/nologin hindama

WORKDIR /app
COPY --from=build --chown=root:root /app/.venv /app/.venv
# Migrations travel with the image so a deploy runs exactly the schema it was built with.
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root migrations ./migrations

USER hindama
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]

# --no-access-log: the app writes its own access log without query strings.
CMD ["uvicorn", "hindama.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--workers", "2"]
