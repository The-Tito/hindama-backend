import httpx
import pytest
from fastapi import FastAPI

from hindama.api.health import check_database


@pytest.fixture(autouse=True)
def healthy(app: FastAPI) -> None:
    app.dependency_overrides[check_database] = lambda: True


async def test_generates_a_request_id(client: httpx.AsyncClient) -> None:
    first = (await client.get("/health")).headers["x-request-id"]
    second = (await client.get("/health")).headers["x-request-id"]

    assert len(first) == 36
    assert first != second


async def test_keeps_a_valid_incoming_request_id(client: httpx.AsyncClient) -> None:
    response = await client.get("/health", headers={"X-Request-Id": "next-abc_123.req"})

    assert response.headers["x-request-id"] == "next-abc_123.req"


@pytest.mark.parametrize("incoming", ["short", "x" * 129, "bad id\nwith newline", "<script>"])
async def test_replaces_an_invalid_incoming_request_id(
    client: httpx.AsyncClient, incoming: str
) -> None:
    response = await client.get("/health", headers={"X-Request-Id": incoming.replace("\n", " ")})

    assert response.headers["x-request-id"] != incoming
    assert len(response.headers["x-request-id"]) == 36
