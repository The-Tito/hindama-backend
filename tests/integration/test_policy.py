"""Access policy per operation (CU-11; RF-35, RF-39 to RF-43; RN-02, RN-08), against PostgreSQL."""

import json
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from hindama.models import Operation
from tests.integration.conftest import Analyst

SECURED = {"security": [{"bearer": []}], "responses": {"200": {"description": "ok"}}}
OPEN = {"responses": {"200": {"description": "ok"}}}


def contract(paths: dict[str, Any]) -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "API de pedidos", "version": "1.0"},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "paths": paths,
    }


PATHS = {
    "/health": {"get": OPEN},
    "/orders": {"get": SECURED, "post": SECURED},
    "/orders/{orderId}": {"get": SECURED, "delete": SECURED},
    "/orders/{orderId}/items/{itemId}": {"get": SECURED},
    "/admin/users": {"get": SECURED},
}


class Project:
    def __init__(self, analyst: Analyst, project_id: str) -> None:
        self.analyst = analyst
        self.id = project_id

    async def import_contract(self, paths: dict[str, Any]) -> None:
        files = {"file": ("openapi.json", json.dumps(contract(paths)).encode(), "application/json")}
        response = await self.analyst.request("POST", f"/projects/{self.id}/contracts", files=files)
        assert response.status_code in (200, 201), response.text

    async def operations(self, **params: Any) -> dict[str, dict[str, Any]]:
        response = await self.analyst.request(
            "GET", f"/projects/{self.id}/operations", params=params
        )
        return {f"{o['method']} {o['path']}": o for o in response.json()["items"]}

    async def patch(self, operation_id: str, body: Any) -> Any:
        return await self.analyst.request(
            "PATCH", f"/projects/{self.id}/operations/{operation_id}", json=body
        )

    async def bulk(self, body: Any) -> Any:
        return await self.analyst.request("POST", f"/projects/{self.id}/policy", json=body)


@pytest.fixture
async def project(ana: Analyst) -> Project:
    created = Project(ana, (await ana.create())["id"])
    await created.import_contract(PATHS)
    return created


# ------------------------------------------------------------------ proposals at import


async def test_import_proposes_without_confirming(project: Project) -> None:
    ops = await project.operations()
    assert {key: op["suggested_policy"] for key, op in ops.items()} == {
        "GET /health": "public",
        "GET /orders": "authenticated",
        "POST /orders": "authenticated",
        "GET /orders/{orderId}": "owner_only",
        "DELETE /orders/{orderId}": "owner_only",
        "GET /orders/{orderId}/items/{itemId}": "owner_only",
        "GET /admin/users": "admin_only",
    }
    assert all(op["policy"] is None and op["confirmed_at"] is None for op in ops.values())
    assert ops["GET /orders/{orderId}/items/{itemId}"]["resource_parameters"] == [
        {"name": "orderId", "resource_type": "orders"},
        {"name": "itemId", "resource_type": "items"},
    ]


async def test_a_reimport_keeps_what_the_analyst_chose(project: Project) -> None:
    ops = await project.operations()
    detail = ops["GET /orders/{orderId}/items/{itemId}"]["id"]
    response = await project.patch(
        detail,
        {
            "policy": "owner_or_admin",
            "owner_field": "owner.id",
            "resource_parameters": [
                {"name": "orderId", "resource_type": "pedido"},
                {"name": "itemId", "resource_type": "articulo"},
            ],
        },
    )
    assert response.status_code == 200, response.text

    # The parameter is renamed in the new version: same operation, one parameter gone.
    paths = {k: v for k, v in PATHS.items() if k != "/orders/{orderId}/items/{itemId}"}
    paths["/orders/{orderId}/items/{lineId}"] = {"get": SECURED}
    await project.import_contract(paths)

    after = (await project.operations())["GET /orders/{orderId}/items/{lineId}"]
    assert after["id"] == detail
    assert (after["policy"], after["owner_field"]) == ("owner_or_admin", "owner.id")
    assert after["resource_parameters"] == [{"name": "orderId", "resource_type": "pedido"}]
    assert after["suggested_policy"] == "authenticated"  # recomputed from what is left


async def test_an_untouched_operation_gets_the_new_proposal(project: Project) -> None:
    paths = {**PATHS, "/orders/{orderId}": {"get": OPEN, "delete": SECURED}}
    await project.import_contract(paths)
    assert (await project.operations())["GET /orders/{orderId}"]["suggested_policy"] == "public"


# ------------------------------------------------------------------ one operation


async def test_confirm_a_template(project: Project, owner: AsyncEngine) -> None:
    op = (await project.operations())["GET /orders/{orderId}"]
    response = await project.patch(op["id"], {"policy": "owner_only", "owner_field": "orderId"})
    assert response.status_code == 200
    body = response.json()
    assert (body["policy"], body["owner_field"]) == ("owner_only", "orderId")
    assert body["confirmed_at"] is not None and body["modified_at"] is not None
    assert body["path"] == "/orders/{orderId}"  # the full Operation comes back
    async with AsyncSession(owner) as db:
        row = await db.get(Operation, uuid.UUID(op["id"]))
        assert row is not None and row.modified_by is not None  # RF-43: who


async def test_ownership_needs_the_owner_field(project: Project) -> None:
    op = (await project.operations())["GET /orders/{orderId}"]
    for policy in ("owner_only", "owner_or_admin"):
        response = await project.patch(op["id"], {"policy": policy})
        assert (response.status_code, response.json()["code"]) == (
            422,
            "policy.owner_field_required",
        )
    await project.patch(op["id"], {"policy": "owner_only", "owner_field": "orderId"})
    response = await project.patch(op["id"], {"owner_field": None})
    assert response.json()["code"] == "policy.owner_field_required"


async def test_another_template_drops_the_owner_field(project: Project) -> None:
    op = (await project.operations())["GET /orders/{orderId}"]
    await project.patch(op["id"], {"policy": "owner_only", "owner_field": "orderId"})
    body = (await project.patch(op["id"], {"policy": "authenticated"})).json()
    assert (body["policy"], body["owner_field"]) == ("authenticated", None)


async def test_the_owner_field_alone_keeps_the_confirmation(project: Project) -> None:
    op = (await project.operations())["GET /orders/{orderId}"]
    first = (await project.patch(op["id"], {"policy": "owner_only", "owner_field": "a"})).json()
    body = (await project.patch(op["id"], {"owner_field": "user.id"})).json()
    assert (body["policy"], body["owner_field"]) == ("owner_only", "user.id")
    assert body["confirmed_at"] == first["confirmed_at"]


async def test_null_leaves_it_unconfirmed(project: Project) -> None:
    op = (await project.operations())["GET /orders"]
    await project.patch(op["id"], {"policy": "public"})
    body = (await project.patch(op["id"], {"policy": None})).json()
    assert (body["policy"], body["confirmed_at"]) == (None, None)
    assert body["suggested_policy"] == "authenticated"  # the proposal stays


async def test_resource_parameters_must_be_path_parameters(project: Project) -> None:
    op = (await project.operations())["GET /orders/{orderId}"]
    for parameters in (
        [{"name": "userId", "resource_type": "users"}],
        [{"name": "orderId", "resource_type": "a"}, {"name": "orderId", "resource_type": "b"}],
    ):
        response = await project.patch(op["id"], {"resource_parameters": parameters})
        assert response.json()["code"] == "operation.unknown_parameter"
        assert response.json()["errors"][0]["field"].startswith("resource_parameters.")
    body = (await project.patch(op["id"], {"resource_parameters": []})).json()
    assert body["resource_parameters"] == []
    assert body["policy"] is None  # untouched


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"policy": "everyone"},
        {"owner_field": ""},
        {"resource_parameters": [{"name": "orderId"}]},
        {"resource_parameters": [{"name": "x", "resource_type": "y"}] * 21},
        {"policy": "public", "extra": 1},
    ],
)
async def test_malformed_updates(project: Project, body: dict[str, Any]) -> None:
    op = (await project.operations())["GET /orders"]
    response = await project.patch(op["id"], body)
    assert response.status_code == 422
    assert response.json()["code"].startswith("validation.")


async def test_a_retired_operation_cannot_change(project: Project) -> None:
    op = (await project.operations())["GET /admin/users"]
    await project.import_contract({k: v for k, v in PATHS.items() if k != "/admin/users"})
    response = await project.patch(op["id"], {"policy": "admin_only"})
    assert (response.status_code, response.json()["code"]) == (409, "operation.retired")


# ------------------------------------------------------------------ in bulk (RF-42)


async def test_apply_a_template_to_a_path(project: Project) -> None:
    ops = await project.operations()
    ids = [ops["DELETE /orders/{orderId}"]["id"], ops["GET /orders/{orderId}"]["id"]]
    response = await project.bulk(
        {"operation_ids": ids, "policy": "owner_or_admin", "owner_field": "orderId"}
    )
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert [(i["method"], i["path"]) for i in items] == [
        ("DELETE", "/orders/{orderId}"),
        ("GET", "/orders/{orderId}"),
    ]  # by path, then method
    assert all(i["policy"] == "owner_or_admin" and i["confirmed_at"] for i in items)

    plain = await project.bulk({"operation_ids": ids, "policy": "admin_only", "owner_field": "x"})
    assert all(i["owner_field"] is None for i in plain.json()["items"])


async def test_bulk_is_all_or_nothing(project: Project) -> None:
    ops = await project.operations()
    good = ops["GET /orders"]["id"]
    unknown = str(uuid.uuid4())
    response = await project.bulk({"operation_ids": [good, unknown], "policy": "public"})
    assert (response.status_code, response.json()["code"]) == (422, "operation.not_found")
    assert [e["field"] for e in response.json()["errors"]] == ["operation_ids.1"]
    assert (await project.operations())["GET /orders"]["policy"] is None

    response = await project.bulk({"operation_ids": [good], "policy": "owner_only"})
    assert response.json()["code"] == "policy.owner_field_required"

    retired = ops["GET /admin/users"]["id"]
    await project.import_contract({k: v for k, v in PATHS.items() if k != "/admin/users"})
    response = await project.bulk({"operation_ids": [good, retired], "policy": "public"})
    assert (response.status_code, response.json()["code"]) == (409, "operation.retired")
    assert (await project.operations())["GET /orders"]["policy"] is None


@pytest.mark.parametrize(
    "body",
    [
        {"operation_ids": [], "policy": "public"},
        {"operation_ids": ["no-es-uuid"], "policy": "public"},
        {"operation_ids": [str(uuid.UUID(int=1))] * 2, "policy": "public"},
        {"operation_ids": [str(uuid.UUID(int=1))]},
        {"operation_ids": [str(uuid.UUID(int=i)) for i in range(501)], "policy": "public"},
    ],
)
async def test_malformed_bulk(project: Project, body: dict[str, Any]) -> None:
    response = await project.bulk(body)
    assert response.status_code == 422
    assert response.json()["code"].startswith("validation.")


# ------------------------------------------------------------------ isolation and modules


async def test_another_analysts_operations_do_not_exist(project: Project, new_analyst: Any) -> None:
    op = (await project.operations())["GET /orders"]
    intruder: Analyst = new_analyst()
    await intruder.accept_terms()
    response = await intruder.request(
        "PATCH", f"/projects/{project.id}/operations/{op['id']}", json={"policy": "public"}
    )
    assert response.status_code == 404
    response = await intruder.request(
        "POST",
        f"/projects/{project.id}/policy",
        json={"operation_ids": [op["id"]], "policy": "public"},
    )
    assert response.status_code == 404

    theirs = Project(intruder, (await intruder.create())["id"])
    response = await theirs.bulk({"operation_ids": [op["id"]], "policy": "public"})
    assert response.json()["code"] == "operation.not_found"  # not theirs: unknown, not 403
    assert (await project.operations())["GET /orders"]["policy"] is None


async def test_confirmed_policies_unlock_the_authorization_modules(
    ana: Analyst, project: Project
) -> None:
    """RF-45, RN-08: only confirmed templates count, not proposals."""

    async def missing(module: str) -> list[str]:
        dashboard = (await ana.request("GET", f"/projects/{project.id}")).json()
        return next(m["missing"] for m in dashboard["modules"] if m["module"] == module)

    assert "policy_unconfirmed" in await missing("function_access")
    assert "policy_unconfirmed" in await missing("object_access")
    ops = await project.operations()
    await project.patch(ops["GET /admin/users"]["id"], {"policy": "admin_only"})
    await project.patch(
        ops["GET /orders/{orderId}"]["id"], {"policy": "owner_only", "owner_field": "x"}
    )
    assert "policy_unconfirmed" not in await missing("function_access")
    assert "policy_unconfirmed" not in await missing("object_access")


async def test_an_unknown_operation_does_not_exist(project: Project) -> None:
    response = await project.patch(str(uuid.uuid4()), {"policy": "public"})
    assert (response.status_code, response.json()["code"]) == (404, "resource.not_found")


async def test_an_edited_operation_survives_an_identical_reimport(project: Project) -> None:
    op = (await project.operations())["GET /orders/{orderId}"]
    chosen = [{"name": "orderId", "resource_type": "pedido"}]
    await project.patch(op["id"], {"resource_parameters": chosen})
    await project.import_contract({**PATHS, "/extra": {"get": OPEN}})  # a new version, same op
    after = (await project.operations())["GET /orders/{orderId}"]
    assert after["resource_parameters"] == chosen
    assert after["suggested_policy"] == "owner_only"
