"""Access policy of each operation (F-07, CU-11; RF-35, RF-39 to RF-43; RN-08).

Setting a template is confirming it: only confirmed policies drive the authorization modules. The
system's proposal (`suggested_policy`) is never used on its own.
"""

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.auth import CurrentUser
from hindama.core.errors import ConflictError, FieldIssue, NotFoundError, UnprocessableError
from hindama.core.openapi_import import path_parameters
from hindama.models import Operation, OperationVersion
from hindama.models.enums import OWNERSHIP_POLICIES, Policy
from hindama.repositories import contracts as repository
from hindama.repositories import projects as projects_repository
from hindama.schemas.contracts import ResourceParameter

log = structlog.get_logger(__name__)


def _owner_field_required() -> UnprocessableError:
    return UnprocessableError(
        "policy.owner_field_required",
        "Falta el campo del propietario",
        "Las plantillas de propiedad necesitan el parámetro o campo que identifica al dueño, por "
        "ejemplo userId u owner.id.",
        [FieldIssue("owner_field", "policy.owner_field_required", "Obligatorio aquí.")],
    )


def _retired() -> ConflictError:
    return ConflictError(
        "operation.retired",
        "Operación retirada",
        "La operación ya no aparece en el contrato vigente; su política no se puede cambiar.",
    )


def _apply(
    operation: Operation, policy: Policy | None, owner_field: str | None, *, confirm: bool
) -> None:
    """RF-41: an ownership template needs its owner field; another template drops a stale one.
    `confirm` when the template itself was sent: setting it is confirming it (RN-08)."""
    if policy in OWNERSHIP_POLICIES and owner_field is None:
        raise _owner_field_required()
    if policy is not None and policy not in OWNERSHIP_POLICIES:
        owner_field = None
    operation.policy = policy
    operation.owner_field = owner_field
    if confirm:
        operation.confirmed_at = None if policy is None else func.now()


def _touch(operation: Operation, user: CurrentUser) -> None:
    operation.modified_at = func.now()  # RF-43: who and when
    operation.modified_by = user.id


async def _project(session: AsyncSession, project_id: UUID) -> None:
    if await projects_repository.get(session, project_id) is None:
        raise NotFoundError()


async def _reloaded(
    session: AsyncSession, project_id: UUID, operations: list[Operation]
) -> list[tuple[Operation, OperationVersion]]:
    await session.flush()
    for operation in operations:
        await session.refresh(operation)
    return await repository.describe(session, project_id, operations)


async def update_operation(
    session: AsyncSession,
    user: CurrentUser,
    project_id: UUID,
    operation_id: UUID,
    changes: dict[str, Any],
) -> tuple[Operation, OperationVersion]:
    """PATCH: confirm or change the template (RF-39 to RF-41) and fix the resource parameters
    (RF-35)."""
    await _project(session, project_id)
    found = await repository.operations_for_update(session, project_id, [operation_id])
    if not found:
        raise NotFoundError()
    operation = found[0]
    if operation.retired_at is not None:
        raise _retired()
    if not changes:
        raise UnprocessableError(
            "validation.failed",
            "Datos inválidos",
            "Envía al menos un campo para modificar.",
            [FieldIssue(None, "validation.required", "Envía al menos un campo.")],
        )
    if "resource_parameters" in changes:
        operation.resource_parameters = _resource_parameters(
            operation, changes["resource_parameters"]
        )
    if "policy" in changes or "owner_field" in changes:
        policy = changes.get("policy", operation.policy)
        _apply(
            operation,
            None if policy is None else Policy(policy),
            changes.get("owner_field", operation.owner_field),
            confirm="policy" in changes,
        )
    _touch(operation, user)
    log.info(
        "operation_policy_updated",
        project_id=str(project_id),
        operation_id=str(operation.id),
        policy=operation.policy,
        fields=sorted(changes),
    )
    return (await _reloaded(session, project_id, [operation]))[0]


def _resource_parameters(
    operation: Operation, parameters: list[ResourceParameter]
) -> list[dict[str, str]]:
    """RF-35: each one a path parameter of this operation, at most once."""
    names = set(path_parameters(operation.path))
    seen: set[str] = set()
    issues = []
    for index, parameter in enumerate(parameters):
        if parameter.name not in names or parameter.name in seen:
            issues.append(
                FieldIssue(
                    f"resource_parameters.{index}.name",
                    "operation.unknown_parameter",
                    "No es un parámetro de ruta de la operación, o está repetido.",
                )
            )
        seen.add(parameter.name)
    if issues:
        raise UnprocessableError(
            "operation.unknown_parameter",
            "Parámetro desconocido",
            "Los parámetros de recurso deben ser parámetros de ruta de la operación.",
            issues,
        )
    return [p.model_dump() for p in parameters]


async def apply_policy(
    session: AsyncSession,
    user: CurrentUser,
    project_id: UUID,
    operation_ids: list[UUID],
    policy: Policy,
    owner_field: str | None,
) -> list[tuple[Operation, OperationVersion]]:
    """RF-42: one template on many operations, all or nothing. Confirms it on all (RN-08)."""
    await _project(session, project_id)
    if policy in OWNERSHIP_POLICIES and owner_field is None:
        raise _owner_field_required()
    operations = await repository.operations_for_update(session, project_id, operation_ids)
    found = {operation.id for operation in operations}
    missing = [
        FieldIssue(f"operation_ids.{index}", "operation.not_found", "No es una operación.")
        for index, operation_id in enumerate(operation_ids)
        if operation_id not in found
    ]
    if missing:
        raise UnprocessableError(
            "operation.not_found",
            "Operación desconocida",
            "Alguna de las operaciones no pertenece al proyecto.",
            missing,
        )
    if any(operation.retired_at is not None for operation in operations):
        raise _retired()
    for operation in operations:
        _apply(operation, policy, owner_field, confirm=True)
        _touch(operation, user)
    log.info(
        "operation_policy_applied",
        project_id=str(project_id),
        policy=policy.value,
        operations=len(operations),
    )
    return await _reloaded(session, project_id, operations)
