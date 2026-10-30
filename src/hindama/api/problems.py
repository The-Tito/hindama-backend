"""Turns every error into a Problem Details response (convenciones.md, section 8).

FastAPI's default formats (`{"detail": ...}` and its 422 body) never reach the client.
"""

from collections.abc import Sequence
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from hindama.core.errors import AppError, FieldIssue
from hindama.core.request_context import get_request_id, new_request_id

PROBLEM_MEDIA_TYPE = "application/problem+json"

# Pydantic error types -> stable field error codes.
_LENGTH_ERRORS = {"string_too_short", "string_too_long", "too_short", "too_long"}
_FIELD_MESSAGES = {
    "validation.required": "Este campo es obligatorio.",
    "validation.length": "La longitud no es válida.",
    "validation.format": "El valor no tiene el formato esperado.",
}
# Location prefixes FastAPI adds that are not part of the field name.
_LOCATION_PREFIXES = {"body", "query", "path", "header", "cookie"}


def problem_response(
    status: int,
    code: str,
    title: str,
    detail: str,
    errors: Sequence[FieldIssue] = (),
    extensions: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": f"urn:hindama:error:{code}",
        "title": title,
        "status": status,
        "detail": detail,
        "code": code,
        "request_id": get_request_id() or new_request_id(),
        "errors": [{"field": e.field, "code": e.code, "message": e.message} for e in errors],
    }
    if extensions:
        body.update(extensions)
    return JSONResponse(body, status_code=status, media_type=PROBLEM_MEDIA_TYPE, headers=headers)


def internal_error_response() -> JSONResponse:
    """500 without any internal detail (RNF-07): only the code and the request id."""
    return problem_response(
        status=500,
        code="internal",
        title="Error interno",
        detail=(
            "Ocurrió un error inesperado. Si persiste, comparte el identificador de la petición."
        ),
    )


_UNAUTHENTICATED = {
    "auth.required": ("Autenticación requerida", "La petición no incluye un token de acceso."),
    "auth.invalid_token": (
        "Token inválido",
        "El token de acceso venció o no es válido. Inicia sesión de nuevo.",
    ),
}


def unauthenticated_response(code: str) -> JSONResponse:
    """401 with `WWW-Authenticate: Bearer` (RFC 6750, convenciones.md section 8)."""
    title, detail = _UNAUTHENTICATED[code]
    challenge = "Bearer" if code == "auth.required" else 'Bearer error="invalid_token"'
    return problem_response(401, code, title, detail, headers={"WWW-Authenticate": challenge})


def app_error_response(exc: AppError) -> JSONResponse:
    return problem_response(exc.status, exc.code, exc.title, exc.detail, exc.errors, exc.extensions)


def _field_issue(error: dict[str, Any]) -> FieldIssue:
    location = [str(part) for part in error.get("loc", ())]
    if location and location[0] in _LOCATION_PREFIXES:
        location = location[1:]
    kind = error.get("type", "")
    if kind == "missing":
        code = "validation.required"
    elif kind in _LENGTH_ERRORS:
        code = "validation.length"
    else:
        code = "validation.format"
    return FieldIssue(
        field=".".join(location) or None,
        code=code,
        message=_FIELD_MESSAGES[code],
    )


async def _handle_app_error(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AppError):  # pragma: no cover - registered only for AppError
        raise exc
    return app_error_response(exc)


async def _handle_validation_error(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        raise exc
    raw_errors = list(exc.errors())
    if any(e.get("type") == "json_invalid" for e in raw_errors):
        return problem_response(
            400,
            "request.malformed",
            "Petición mal formada",
            "El cuerpo de la petición no es un JSON válido.",
        )
    # Never echo `input` or `ctx` back: they may contain what the user sent (e.g. a credential).
    return problem_response(
        422,
        "validation.failed",
        "Datos inválidos",
        "Uno o más campos no son válidos.",
        [_field_issue(e) for e in raw_errors],
    )


async def _handle_http_exception(_: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # pragma: no cover
        raise exc
    if exc.status_code == 404:
        return problem_response(404, "resource.not_found", "No encontrado", "El recurso no existe.")
    if exc.status_code == 405:
        return problem_response(
            405,
            "request.method_not_allowed",
            "Método no permitido",
            "La ruta no acepta este método HTTP.",
            headers=dict(exc.headers or {}),
        )
    if exc.status_code == 400:
        return problem_response(
            400, "request.malformed", "Petición mal formada", "La petición no se pudo interpretar."
        )
    return problem_response(
        exc.status_code,
        "request.error",
        "Error en la petición",
        "La petición no se pudo completar.",
        headers=dict(exc.headers or {}),
    )


def register_problem_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
