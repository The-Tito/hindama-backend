"""The generated OpenAPI document (RNF-22), aligned with the contract (ADR-016).

Authentication lives in a middleware, which FastAPI cannot see; the security scheme is declared here
as in hindama-docs/03-api/openapi.yaml: bearer token everywhere, `security: []` on public paths.
"""

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel

from hindama.api.problems import PROBLEM_MEDIA_TYPE
from hindama.schemas.common import Problem
from hindama.schemas.verification import VerificationProblem

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


# Operations whose 422 can also be a Problem with extra members (oneOf, as in the contract).
_SPECIFIC_PROBLEMS: dict[str, type[BaseModel]] = {"verifyOwnership": VerificationProblem}


def _problem_schemas() -> dict[str, Any]:
    """`Problem`, its variants and `FieldError`, from the models that describe every error."""
    result: dict[str, Any] = {}
    models: list[type[BaseModel]] = [Problem, *_SPECIFIC_PROBLEMS.values()]
    for model in models:
        schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
        result.update(schema.pop("$defs", {}))
        result[model.__name__] = schema
    return result


def _schema_ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/schemas/{name}"}


def _document_problem_details(schema: dict[str, Any]) -> None:
    schemas = schema.setdefault("components", {}).setdefault("schemas", {})
    for name in _FASTAPI_VALIDATION_SCHEMAS:
        schemas.pop(name, None)
    schemas.update(_problem_schemas())
    for operations in schema.get("paths", {}).values():
        for operation in operations.values():
            if "422" in operation.get("responses", {}):
                specific = _SPECIFIC_PROBLEMS.get(operation.get("operationId", ""))
                body = (
                    PROBLEM_REF
                    if specific is None
                    else {"oneOf": [_schema_ref(specific.__name__), PROBLEM_REF]}
                )
                operation["responses"]["422"] = {
                    "description": "Datos inválidos (`validation.*`) o una regla del negocio.",
                    "content": {PROBLEM_MEDIA_TYPE: {"schema": body}},
                }


# Multipart bodies FastAPI describes from loose form fields; the contract has a closed object, of
# which the endpoint checks "exactly one of" itself (`contract.source_required`).
_FORM_BODIES: dict[str, tuple[str, dict[str, Any]]] = {
    "importContract": (
        "ContractImport",
        {
            "type": "object",
            "additionalProperties": False,
            "description": "Exactamente uno de `file` o `url`.",
            "properties": {
                "file": {"type": "string", "format": "binary"},
                "url": {"type": "string", "format": "uri", "maxLength": 2048},
            },
        },
    )
}


def _document_form_bodies(schema: dict[str, Any]) -> None:
    schemas = schema.setdefault("components", {}).setdefault("schemas", {})
    for operations in schema.get("paths", {}).values():
        for operation in operations.values():
            form = _FORM_BODIES.get(operation.get("operationId", ""))
            body = operation.get("requestBody")
            if form is None or body is None:
                continue
            name, definition = form
            for media in body.get("content", {}).values():
                generated = media.get("schema", {}).get("$ref", "").rsplit("/", 1)[-1]
                schemas.pop(generated, None)
                media["schema"] = _schema_ref(name)
            body["required"] = True
            schemas[name] = definition


def _optional_query_parameters(schema: dict[str, Any]) -> None:
    """An optional query parameter is absent or has a value: it is never JSON `null`. FastAPI
    writes `X | None = None` as `anyOf [X, null]`; the contract writes X."""
    for operations in schema.get("paths", {}).values():
        for operation in operations.values():
            for parameter in operation.get("parameters", []):
                options = parameter.get("schema", {}).get("anyOf")
                if parameter.get("in") != "query" or parameter.get("required") or not options:
                    continue
                rest = [option for option in options if option.get("type") != "null"]
                if len(rest) == 1 and len(rest) < len(options):
                    others = {k: v for k, v in parameter["schema"].items() if k != "anyOf"}
                    parameter["schema"] = {**others, **rest[0]}


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
            _document_form_bodies(schema)
            _optional_query_parameters(schema)
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
