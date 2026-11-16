"""`PATCH /projects/{project_id}/operations/{operation_id}` and `POST /projects/{project_id}/policy`
(CU-11; RF-35, RF-39 to RF-43; RN-08)."""

from uuid import UUID

from fastapi import APIRouter

from hindama.api.contracts import operation_view
from hindama.api.dependencies import Analyst, DbSession
from hindama.schemas.contracts import Operation, OperationUpdate, PolicyBulkResult, PolicyBulkUpdate
from hindama.services import policy as service

router = APIRouter(tags=["Policy"])


@router.patch(
    "/projects/{project_id}/operations/{operation_id}",
    operation_id="updateOperation",
    summary="Política y parámetros de recurso de una operación",
)
async def update_operation(
    project_id: UUID, operation_id: UUID, body: OperationUpdate, user: Analyst, db: DbSession
) -> Operation:
    changes = {name: getattr(body, name) for name in body.model_fields_set}
    row, version = await service.update_operation(db, user, project_id, operation_id, changes)
    return operation_view(row, version)


@router.post(
    "/projects/{project_id}/policy",
    operation_id="applyPolicy",
    summary="Aplicar una plantilla a varias operaciones",
)
async def apply_policy(
    project_id: UUID, body: PolicyBulkUpdate, user: Analyst, db: DbSession
) -> PolicyBulkResult:
    rows = await service.apply_policy(
        db, user, project_id, body.operation_ids, body.policy, body.owner_field
    )
    return PolicyBulkResult(items=[operation_view(row, version) for row, version in rows])
