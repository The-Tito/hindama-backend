"""The generated OpenAPI document (RNF-22), aligned with the contract (ADR-016).

Authentication lives in a middleware, which FastAPI cannot see; the security scheme is declared here
as in hindama-docs/03-api/openapi.yaml: bearer token everywhere, `security: []` on public paths.
"""

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from hindama.api.problems import PROBLEM_MEDIA_TYPE
from hindama.schemas.common import Problem

BEARER_SCHEME = {
    "type": "http",
    "scheme": "bearer",
    "bearerFormat": "JWT",
    "description": "Access token de Amazon Cognito. Lo agrega el servidor de Next.js.",
}


PROBLEM_REF = {"$ref": "#/components/schemas/Problem"}
# FastAPI documents its own 422 body; the API never sends it (api/problems.py answers Problem
# Details). Found by PT-03: the generated document described a format no response used.
_FASTAPI_VALIDATION_SCHEMAS = ("HTTPValidationError", "ValidationError")


def _problem_schemas() -> dict[str, Any]:
    """`Problem` and `FieldError`, from the same models that build every error response."""
    schema = Problem.model_json_schema(ref_template="#/components/schemas/{model}")
    definitions: dict[str, Any] = schema.pop("$defs", {})
    return {"Problem": schema, **definitions}


def _document_problem_details(schema: dict[str, Any]) -> None:
    schemas = schema.setdefault("components", {}).setdefault("schemas", {})
    for name in _FASTAPI_VALIDATION_SCHEMAS:
        schemas.pop(name, None)
    schemas.update(_problem_schemas())
    for operations in schema.get("paths", {}).values():
        for operation in operations.values():
            if "422" in operation.get("responses", {}):
                operation["responses"]["422"] = {
                    "description": "Datos inválidos (`validation.*`) o una regla del negocio.",
                    "content": {PROBLEM_MEDIA_TYPE: {"schema": PROBLEM_REF}},
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
            _document_problem_details(schema)
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
