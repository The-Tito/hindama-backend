"""`/projects/{project_id}/verification` (CU-07; RF-17 to RF-21; RN-01, RN-02), against PostgreSQL.

The real checker goes through the SSRF guard to a local server that plays the analyst's API at
`api.hindama.test`; only loopback is allowed on top of the production policy. TXT records are fake.
"""

from collections.abc import Iterator
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from hindama.core.ownership import NetworkOwnershipChecker, OwnershipChecker
from hindama.models import Project
from tests.integration.conftest import Analyst
from tests.ownership import FakeTxtResolver
from tests.servers import HOST, LOOPBACK, LocalServer, ScriptedResolver, allow_loopback

# What the local server answers on the well-known path, and how many times it was asked.
FILE: dict[str, Any] = {}


async def well_known(_: Request) -> Response:
    FILE["hits"] += 1
    return Response(FILE["body"], status_code=FILE["status"], media_type="text/plain")


APP = Starlette(routes=[Route("/.well-known/hindama-verificacion.txt", well_known)])


@pytest.fixture(scope="module")
def server() -> Iterator[LocalServer]:
    with LocalServer(APP) as running:
        yield running


@pytest.fixture(autouse=True)
def nothing_published() -> None:
    FILE.clear()
    FILE.update(status=404, body="Not found", hits=0)


@pytest.fixture
def txt() -> FakeTxtResolver:
    return FakeTxtResolver()


@pytest.fixture
def ownership_checker(txt: FakeTxtResolver) -> OwnershipChecker:
    return NetworkOwnershipChecker(
        resolver=ScriptedResolver([LOOPBACK]),
        txt_resolver=txt,
        address_policy=allow_loopback,
    )


async def create(analyst: Analyst, server: LocalServer) -> dict[str, Any]:
    return await analyst.create(base_url=f"http://{HOST}:{server.port}/v1")


def path(project: dict[str, Any]) -> str:
    return f"/projects/{project['id']}/verification"


async def stored(owner: AsyncEngine, project_id: str) -> Project:
    async with AsyncSession(owner) as session:
        project = await session.get(Project, UUID(project_id))
    assert project is not None
    return project


# ------------------------------------------------------------------ instructions


async def test_instructions_of_a_new_project(ana: Analyst, server: LocalServer) -> None:
    project = await create(ana, server)

    response = await ana.request("GET", path(project))

    assert response.status_code == 200
    body = response.json()
    code = body["code"]
    assert code.startswith("hindama-verificacion=")
    assert len(code.removeprefix("hindama-verificacion=")) == 32  # RF-17
    assert body == {
        "status": "pending",
        "host": HOST,
        "code": code,
        "method": None,
        "verified_at": None,
        "file": {
            "url": f"http://{HOST}:{server.port}/.well-known/hindama-verificacion.txt",
            "content": code,
        },
        "dns": {"name": f"_hindama-verificacion.{HOST}", "type": "TXT", "value": code},
    }


async def test_each_project_has_its_own_code(ana: Analyst, server: LocalServer) -> None:
    first = (await ana.request("GET", path(await create(ana, server)))).json()
    second = (await ana.request("GET", path(await create(ana, server)))).json()
    assert first["code"] != second["code"]


# ------------------------------------------------------------------ verify (CU-07)


async def test_verify_with_the_file(ana: Analyst, server: LocalServer, owner: AsyncEngine) -> None:
    project = await create(ana, server)
    code = (await ana.request("GET", path(project))).json()["code"]
    FILE.update(status=200, body=f"{code}\n")

    response = await ana.request("POST", path(project), json={"method": "file"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "verified"
    assert body["method"] == "file"
    assert body["verified_at"] is not None
    assert FILE["hits"] == 1
    saved = await stored(owner, project["id"])
    assert saved.verified_host == HOST
    dashboard = (await ana.request("GET", f"/projects/{project['id']}")).json()
    assert dashboard["verification_status"] == "verified"
    assert "project_not_verified" not in dashboard["modules"][1]["missing"]  # RF-19 lifted


async def test_verify_with_dns(ana: Analyst, server: LocalServer, txt: FakeTxtResolver) -> None:
    project = await create(ana, server)
    code = (await ana.request("GET", path(project))).json()["code"]
    txt.records[f"_hindama-verificacion.{HOST}"] = [code]

    response = await ana.request("POST", path(project), json={"method": "dns"})

    assert response.status_code == 200, response.text
    assert response.json()["method"] == "dns"
    assert FILE["hits"] == 0  # the DNS method never contacts the host


async def test_a_failed_check_says_why(ana: Analyst, server: LocalServer) -> None:
    project = await create(ana, server)
    FILE.update(status=200, body="hindama-verificacion=000000")

    response = await ana.request("POST", path(project), json={"method": "file"})

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["code"] == "verification.content_mismatch"
    assert body["type"] == "urn:hindama:error:verification.content_mismatch"
    assert body["found"] == "HTTP 200: hindama-verificacion=000000"
    assert body["errors"] == []
    status = (await ana.request("GET", path(project))).json()["status"]
    assert status == "pending"


async def test_a_missing_txt_record(ana: Analyst, server: LocalServer) -> None:
    project = await create(ana, server)
    response = await ana.request("POST", path(project), json={"method": "dns"})
    assert response.status_code == 422
    assert response.json()["code"] == "verification.txt_missing"
    assert response.json()["found"] is None


async def test_a_failed_recheck_sends_the_project_back_to_pending(
    ana: Analyst, server: LocalServer, owner: AsyncEngine
) -> None:
    project = await create(ana, server)
    code = (await ana.request("GET", path(project))).json()["code"]
    FILE.update(status=200, body=code)
    assert (await ana.request("POST", path(project), json={"method": "file"})).status_code == 200

    FILE.update(status=404, body="Not found")  # the analyst removed the file
    response = await ana.request("POST", path(project), json={"method": "file"})

    assert response.status_code == 422
    assert response.json()["code"] == "verification.file_not_found"
    saved = await stored(owner, project["id"])  # committed despite the 422
    assert saved.verification_status == "pending"
    assert saved.verification_method is None
    assert saved.verified_at is None
    assert saved.verified_host is None


async def test_an_unknown_method_is_a_field_error(ana: Analyst, server: LocalServer) -> None:
    project = await create(ana, server)
    response = await ana.request("POST", path(project), json={"method": "email"})
    assert response.status_code == 422
    assert response.json()["code"] == "validation.failed"
    assert response.json()["errors"][0]["field"] == "method"


# ------------------------------------------------------------------ isolation (RN-02)


async def test_another_analysts_project_does_not_exist(
    ana: Analyst, new_analyst: Any, server: LocalServer
) -> None:
    project = await create(ana, server)
    code = (await ana.request("GET", path(project))).json()["code"]
    FILE.update(status=200, body=code)
    beto: Analyst = new_analyst()
    await beto.accept_terms()

    read = await beto.request("GET", path(project))
    verify = await beto.request("POST", path(project), json={"method": "file"})

    assert read.status_code == 404
    assert verify.status_code == 404
    assert read.json()["code"] == verify.json()["code"] == "resource.not_found"
    assert FILE["hits"] == 0  # no request on behalf of someone who does not own the project
    assert (await ana.request("GET", path(project))).json()["status"] == "pending"


async def test_a_project_that_does_not_exist(ana: Analyst) -> None:
    missing = "/projects/0192e3a0-0000-7000-8000-000000000000/verification"
    assert (await ana.request("GET", missing)).status_code == 404
    assert (await ana.request("POST", missing, json={"method": "dns"})).status_code == 404
