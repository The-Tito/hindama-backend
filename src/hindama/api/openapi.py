"""The generated OpenAPI document (RNF-22), aligned with the contract (ADR-016).

Authentication lives in a middleware, which FastAPI cannot see; the security scheme is declared here
as in hindama-docs/03-api/openapi.yaml: bearer token everywhere, `security: []` on public paths.
"""

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

BEARER_SCHEME = {
    "type": "http",
    "scheme": "bearer",
    "bearerFormat": "JWT",
    "description": "Access token de Amazon Cognito. Lo agrega el servidor de Next.js.",
}


def install_openapi(app: FastAPI, public_paths: frozenset[str]) -> None:
    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
            schema.setdefault("components", {})["securitySchemes"] = {"bearerAuth": BEARER_SCHEME}
            schema["security"] = [{"bearerAuth": []}]
            for path, operations in schema.get("paths", {}).items():
                if path in public_paths:
                    for operation in operations.values():
                        operation["security"] = []
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
