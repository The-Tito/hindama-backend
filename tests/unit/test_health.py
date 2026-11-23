import httpx
from fastapi import FastAPI

from hindama.api.health import check_database


async def test_health_ok_when_database_answers(app: FastAPI, client: httpx.AsyncClient) -> None:
    app.dependency_overrides[check_database] = lambda: True

    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_health_is_503_problem_when_database_is_down(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    app.dependency_overrides[check_database] = lambda: False

    response = await client.get("/health")

    assert response.status_code == 503
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["code"] == "service.unavailable"


async def test_health_reports_unreachable_database_without_details(
    client: httpx.AsyncClient,
) -> None:
    # The test settings point to a closed port: the real check must fail cleanly.
    response = await client.get("/health")

    assert response.status_code == 503
    assert "localhost" not in response.text
    assert "test:test" not in response.text
