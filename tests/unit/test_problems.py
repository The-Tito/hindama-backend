"""Every error reaches the client as Problem Details (convenciones.md, section 8)."""

from typing import Annotated

import httpx
import pytest
from fastapi import APIRouter, FastAPI, Query
from pydantic import BaseModel, Field

from hindama.core.errors import FieldIssue, NotFoundError, UnprocessableError

PROBLEM_KEYS = {"type", "title", "status", "detail", "code", "request_id", "errors"}


class Payload(BaseModel):
    name: str = Field(min_length=1, max_length=5)
    base_url: str


@pytest.fixture
def app(app: FastAPI) -> FastAPI:
    router = APIRouter()

    @router.post("/echo")
    async def echo(payload: Payload, page: Annotated[int, Query(ge=1)] = 1) -> dict[str, str]:
        return {"name": payload.name}

    @router.get("/missing")
    async def missing() -> None:
        raise NotFoundError()

    @router.get("/rule")
    async def rule() -> None:
        raise UnprocessableError(
            code="url.destination_not_allowed",
            title="Destino no permitido",
            detail="La URL resuelve a una dirección privada.",
            errors=[FieldIssue("base_url", "url.destination_not_allowed", "Dirección privada.")],
        )

    @router.get("/boom")
    async def boom() -> None:
        raise RuntimeError("password=hunter2 at db.internal:5432")

    app.include_router(router)
    return app


def assert_problem(response: httpx.Response, status: int, code: str) -> dict[str, object]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, object] = response.json()
    assert set(body) == PROBLEM_KEYS
    assert body["status"] == status
    assert body["code"] == code
    assert body["type"] == f"urn:hindama:error:{code}"
    assert body["request_id"] == response.headers["x-request-id"]
    return body


async def test_domain_error(client: httpx.AsyncClient) -> None:
    body = assert_problem(await client.get("/rule"), 422, "url.destination_not_allowed")
    assert body["errors"] == [
        {
            "field": "base_url",
            "code": "url.destination_not_allowed",
            "message": "Dirección privada.",
        }
    ]


async def test_not_found_error(client: httpx.AsyncClient) -> None:
    assert_problem(await client.get("/missing"), 404, "resource.not_found")


async def test_unknown_route_is_the_same_not_found(client: httpx.AsyncClient) -> None:
    unknown = assert_problem(await client.get("/does-not-exist"), 404, "resource.not_found")
    known = assert_problem(await client.get("/missing"), 404, "resource.not_found")
    # Same answer for "does not exist" and "not yours" (RN-02): only the request id differs.
    assert {k: v for k, v in unknown.items() if k != "request_id"} == {
        k: v for k, v in known.items() if k != "request_id"
    }


async def test_method_not_allowed(client: httpx.AsyncClient) -> None:
    assert_problem(await client.delete("/health"), 405, "request.method_not_allowed")


async def test_field_validation_errors(client: httpx.AsyncClient) -> None:
    response = await client.post("/echo?page=0", json={"name": "demasiado largo"})

    body = assert_problem(response, 422, "validation.failed")
    errors = body["errors"]
    assert isinstance(errors, list)
    assert {(e["field"], e["code"]) for e in errors} == {
        ("name", "validation.length"),
        ("base_url", "validation.required"),
        ("page", "validation.format"),
    }


async def test_validation_never_echoes_input(client: httpx.AsyncClient) -> None:
    response = await client.post("/echo", json={"name": "s3cr3t-value", "base_url": 987654321})

    assert "s3cr3t-value" not in response.text
    assert "987654321" not in response.text


async def test_malformed_json_is_400(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/echo", content=b"{not json", headers={"content-type": "application/json"}
    )
    assert_problem(response, 400, "request.malformed")


async def test_unhandled_error_is_500_without_internal_details(client: httpx.AsyncClient) -> None:
    response = await client.get("/boom")

    body = assert_problem(response, 500, "internal")
    assert body["errors"] == []
    for leaked in ("hunter2", "db.internal", "RuntimeError", "Traceback"):
        assert leaked not in response.text


async def test_unhandled_error_traceback_is_logged_masked(
    client: httpx.AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    await client.get("/boom")

    logs = capsys.readouterr().out
    assert "unhandled_error" in logs
    assert "RuntimeError" in logs  # the traceback is there for debugging...
    assert "hunter2" not in logs  # ...but not the secret inside it
