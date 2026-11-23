"""Resources by identity (CU-10; RF-37, RF-38; RN-02), against PostgreSQL."""

import json
import uuid
from typing import Any

import pytest

from tests.integration.conftest import Analyst
from tests.integration.test_policy import PATHS, contract


class Project:
    def __init__(self, analyst: Analyst, project_id: str) -> None:
        self.analyst = analyst
        self.id = project_id
        self.path = f"/projects/{project_id}/resources"

    async def identity(self, name: str, role: str = "user") -> str:
        body = {
            "name": name,
            "role": role,
            "auth_type": "bearer",
            "credential": {"token": f"token-de-{name}-1234"},
        }
        response = await self.analyst.request("POST", f"/projects/{self.id}/identities", json=body)
        assert response.status_code == 201, response.text
        identity_id: str = response.json()["id"]
        return identity_id

    async def anonymous(self) -> str:
        page = await self.analyst.request("GET", f"/projects/{self.id}/identities")
        identity_id: str = page.json()["items"][0]["id"]
        return identity_id

    async def request(self, method: str, suffix: str = "", **kwargs: Any) -> Any:
        return await self.analyst.request(method, self.path + suffix, **kwargs)

    async def create(self, identity_id: str, value: str, kind: str = "orders") -> dict[str, Any]:
        response = await self.request(
            "POST", json={"identity_id": identity_id, "resource_type": kind, "value": value}
        )
        assert response.status_code == 201, response.text
        result: dict[str, Any] = response.json()
        return result


@pytest.fixture
async def project(ana: Analyst) -> Project:
    return Project(ana, (await ana.create())["id"])


async def test_register_a_resource(project: Project) -> None:
    ana_id = await project.identity("Ana")
    response = await project.request(
        "POST", json={"identity_id": ana_id, "resource_type": "orders", "value": "101"}
    )
    assert response.status_code == 201
    body = response.json()
    assert response.headers["location"] == f"{project.path}/{body['id']}"
    assert {
        k: body[k] for k in ("identity_id", "resource_type", "value", "source", "confirmed")
    } == {
        "identity_id": ana_id,
        "resource_type": "orders",
        "value": "101",
        "source": "manual",
        "confirmed": True,
    }
    identity = (await project.analyst.request("GET", f"/projects/{project.id}/identities")).json()
    ana = identity["items"][1]
    assert (ana["resource_count"], ana["warnings"]) == (1, [])  # RF-38 lifted


async def test_list_by_type_then_identifier_with_filters(project: Project) -> None:
    ana_id, beto_id = await project.identity("Ana"), await project.identity("Beto")
    await project.create(ana_id, "102")
    await project.create(beto_id, "101")
    await project.create(ana_id, "7", kind="invoices")
    page = (await project.request("GET")).json()
    assert [(r["resource_type"], r["value"]) for r in page["items"]] == [
        ("invoices", "7"),
        ("orders", "101"),
        ("orders", "102"),
    ]
    assert page["total"] == 3
    by_ana = (await project.request("GET", params={"identity_id": ana_id})).json()
    assert [r["value"] for r in by_ana["items"]] == ["7", "102"]
    orders = await project.request("GET", params={"resource_type": "orders", "page_size": 1})
    assert (orders.json()["total"], len(orders.json()["items"])) == (2, 1)


async def test_an_object_has_a_single_owner(project: Project) -> None:
    ana_id, beto_id = await project.identity("Ana"), await project.identity("Beto")
    await project.create(ana_id, "101")
    for identity_id in (beto_id, ana_id):
        response = await project.request(
            "POST", json={"identity_id": identity_id, "resource_type": "orders", "value": "101"}
        )
        assert (response.status_code, response.json()["code"]) == (409, "resource.owned_by_other")
    await project.create(beto_id, "101", kind="invoices")  # another type is another object


async def test_the_owner_must_be_a_live_authenticated_identity(project: Project) -> None:
    ana_id = await project.identity("Ana")
    await project.analyst.request("DELETE", f"/projects/{project.id}/identities/{ana_id}")
    cases = [
        (ana_id, "identity.not_found"),  # deleted
        (str(uuid.uuid4()), "identity.not_found"),
        (await project.anonymous(), "resource.anonymous_owner"),
    ]
    for identity_id, code in cases:
        response = await project.request(
            "POST", json={"identity_id": identity_id, "resource_type": "orders", "value": "1"}
        )
        assert (response.status_code, response.json()["code"]) == (422, code)
        assert response.json()["errors"][0]["field"] == "identity_id"


async def test_edit_move_and_confirm(project: Project) -> None:
    ana_id, beto_id = await project.identity("Ana"), await project.identity("Beto")
    first = await project.create(ana_id, "101")
    await project.create(ana_id, "102")
    path = f"/{first['id']}"
    moved = (await project.request("PATCH", path, json={"identity_id": beto_id})).json()
    assert (moved["identity_id"], moved["value"]) == (beto_id, "101")
    same = await project.request("PATCH", path, json={"value": "101", "confirmed": False})
    assert same.status_code == 200  # its own identifier is not a clash
    assert same.json()["confirmed"] is False
    clash = await project.request("PATCH", path, json={"value": "102"})
    assert (clash.status_code, clash.json()["code"]) == (409, "resource.owned_by_other")
    anonymous = await project.request(
        "PATCH", path, json={"identity_id": await project.anonymous()}
    )
    assert anonymous.json()["code"] == "resource.anonymous_owner"
    empty = await project.request("PATCH", path, json={})
    assert empty.json()["code"] == "validation.failed"


async def test_delete(project: Project) -> None:
    ana_id = await project.identity("Ana")
    created = await project.create(ana_id, "101")
    assert (await project.request("DELETE", f"/{created['id']}")).status_code == 204
    assert (await project.request("DELETE", f"/{created['id']}")).status_code == 404
    assert (await project.request("GET")).json()["total"] == 0
    await project.create(ana_id, "101")  # the identifier is free again


@pytest.mark.parametrize(
    "body",
    [
        {"identity_id": str(uuid.UUID(int=1)), "resource_type": "", "value": "1"},
        {"identity_id": str(uuid.UUID(int=1)), "resource_type": "orders", "value": "a" * 501},
        {"identity_id": str(uuid.UUID(int=1)), "resource_type": "orders", "value": "1\n2"},
        {"identity_id": "no-es-uuid", "resource_type": "orders", "value": "1"},
        {"resource_type": "orders", "value": "1"},
    ],
)
async def test_malformed_resources(project: Project, body: dict[str, Any]) -> None:
    response = await project.request("POST", json=body)
    assert response.status_code == 422
    assert response.json()["code"].startswith("validation.")


async def test_another_analysts_resources_do_not_exist(project: Project, new_analyst: Any) -> None:
    ana_id = await project.identity("Ana")
    created = await project.create(ana_id, "101")
    intruder: Analyst = new_analyst()
    await intruder.accept_terms()
    for method, suffix, body in (
        ("GET", "", None),
        ("POST", "", {"identity_id": ana_id, "resource_type": "orders", "value": "9"}),
        ("PATCH", f"/{created['id']}", {"value": "9"}),
        ("DELETE", f"/{created['id']}", None),
    ):
        response = await intruder.request(method, project.path + suffix, json=body)
        assert response.status_code == 404, (method, suffix)

    # In their own project, Ana's identity and resource are unknown.
    theirs = Project(intruder, (await intruder.create())["id"])
    response = await theirs.request(
        "POST", json={"identity_id": ana_id, "resource_type": "orders", "value": "9"}
    )
    assert response.json()["code"] == "identity.not_found"
    assert (
        await theirs.request("PATCH", f"/{created['id']}", json={"value": "9"})
    ).status_code == 404


async def test_object_access_becomes_available(project: Project) -> None:
    """RF-45, RF-56: verified, a contract, two identities with resources and a confirmed ownership
    policy. Each step removes one requirement."""

    async def missing() -> list[str]:
        dashboard = (await project.analyst.request("GET", f"/projects/{project.id}")).json()
        return next(m["missing"] for m in dashboard["modules"] if m["module"] == "object_access")

    assert await missing() == [
        "project_not_verified",
        "no_contract",
        "insufficient_identities",
        "no_resources",
        "policy_unconfirmed",
    ]
    await project.analyst.request(
        "POST", f"/projects/{project.id}/verification", json={"method": "dns"}
    )
    files = {"file": ("openapi.json", json.dumps(contract(PATHS)).encode(), "application/json")}
    await project.analyst.request("POST", f"/projects/{project.id}/contracts", files=files)
    ana_id, beto_id = await project.identity("Ana"), await project.identity("Beto")
    assert await missing() == ["no_resources", "policy_unconfirmed"]
    await project.create(ana_id, "101")
    await project.create(beto_id, "202")
    assert await missing() == ["policy_unconfirmed"]
    ops = (await project.analyst.request("GET", f"/projects/{project.id}/operations")).json()
    detail = next(
        o for o in ops["items"] if o["method"] == "GET" and o["path"] == "/orders/{orderId}"
    )
    await project.analyst.request(
        "PATCH",
        f"/projects/{project.id}/operations/{detail['id']}",
        json={"policy": "owner_only", "owner_field": "orderId"},
    )
    assert await missing() == []


async def test_function_access_needs_an_identity_that_is_not_admin(project: Project) -> None:
    """RF-57: an administrator and a normal identity. The anonymous one does not count: it is
    tested by Authentication (API2)."""

    async def missing() -> list[str]:
        dashboard = (await project.analyst.request("GET", f"/projects/{project.id}")).json()
        return next(m["missing"] for m in dashboard["modules"] if m["module"] == "function_access")

    await project.identity("Raiz", role="admin")
    assert "insufficient_identities" in await missing()
    assert "no_admin_identity" not in await missing()
    await project.identity("Beto")
    assert "insufficient_identities" not in await missing()
