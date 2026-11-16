"""Resources by identity (F-06, CU-10; RF-37, RF-38).

The object access module (RF-56) asks for another identity's object with each identity: it needs
to know whose each object is. Here they are registered by hand (`source: manual`, confirmed);
discovery (RF-36) arrives with the scanner.
"""

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.errors import ConflictError, FieldIssue, NotFoundError, UnprocessableError
from hindama.models import Resource
from hindama.models.enums import AuthType, ResourceSource
from hindama.repositories import identities as identities_repository
from hindama.repositories import projects as projects_repository
from hindama.repositories import resources as repository

log = structlog.get_logger(__name__)


async def _project(session: AsyncSession, project_id: UUID) -> None:
    # Locked: two requests cannot both take the same object for different identities.
    if await identities_repository.lock_project(session, project_id) is None:
        raise NotFoundError()


async def _owner(session: AsyncSession, project_id: UUID, identity_id: UUID) -> None:
    identity = await identities_repository.get(session, project_id, identity_id)
    if identity is None:
        raise UnprocessableError(
            "identity.not_found",
            "Identidad desconocida",
            "La identidad no existe en el proyecto o fue eliminada.",
            [FieldIssue("identity_id", "identity.not_found", "No es una identidad vigente.")],
        )
    if identity.auth_type == AuthType.NONE:
        raise UnprocessableError(
            "resource.anonymous_owner",
            "La identidad anónima no tiene recursos",
            "Asigna el recurso a una identidad con credencial.",
            [FieldIssue("identity_id", "resource.anonymous_owner", "Es la identidad anónima.")],
        )


async def _single_owner(
    session: AsyncSession,
    project_id: UUID,
    resource_type: str,
    value: str,
    exclude: UUID | None = None,
) -> None:
    taken = await repository.owner_of(session, project_id, resource_type, value)
    if taken is not None and taken.id != exclude:
        raise ConflictError(
            "resource.owned_by_other",
            "El recurso ya tiene dueño",
            "Ese tipo e identificador ya están registrados: un objeto pertenece a una sola "
            "identidad.",
        )


async def list_resources(
    session: AsyncSession,
    project_id: UUID,
    *,
    identity_id: UUID | None,
    resource_type: str | None,
    page: int,
    page_size: int,
) -> tuple[list[Resource], int]:
    if await projects_repository.get(session, project_id) is None:
        raise NotFoundError()
    return await repository.page(
        session,
        project_id,
        identity_id=identity_id,
        resource_type=resource_type,
        page=page,
        page_size=page_size,
    )


async def create_resource(
    session: AsyncSession, project_id: UUID, *, identity_id: UUID, resource_type: str, value: str
) -> Resource:
    """RF-37: a manual resource is confirmed by whoever registers it."""
    await _project(session, project_id)
    await _owner(session, project_id, identity_id)
    await _single_owner(session, project_id, resource_type, value)
    resource = Resource(
        project_id=project_id,
        identity_id=identity_id,
        resource_type=resource_type,
        value=value,
        source=ResourceSource.MANUAL,
        confirmed=True,
    )
    session.add(resource)
    await session.flush()
    await session.refresh(resource)
    log.info("resource_created", project_id=str(project_id), resource_id=str(resource.id))
    return resource


async def update_resource(
    session: AsyncSession, project_id: UUID, resource_id: UUID, changes: dict[str, Any]
) -> Resource:
    await _project(session, project_id)
    resource = await repository.get(session, project_id, resource_id, for_update=True)
    if resource is None:
        raise NotFoundError()
    if not changes:
        raise UnprocessableError(
            "validation.failed",
            "Datos inválidos",
            "Envía al menos un campo para modificar.",
            [FieldIssue(None, "validation.required", "Envía al menos un campo.")],
        )
    if "identity_id" in changes:
        await _owner(session, project_id, changes["identity_id"])
    resource_type = changes.get("resource_type", resource.resource_type)
    value = changes.get("value", resource.value)
    await _single_owner(session, project_id, resource_type, value, exclude=resource.id)
    resource.identity_id = changes.get("identity_id", resource.identity_id)
    resource.resource_type = resource_type
    resource.value = value
    resource.confirmed = changes.get("confirmed", resource.confirmed)
    await session.flush()
    log.info("resource_updated", project_id=str(project_id), resource_id=str(resource.id))
    return resource


async def delete_resource(session: AsyncSession, project_id: UUID, resource_id: UUID) -> None:
    await _project(session, project_id)
    resource = await repository.get(session, project_id, resource_id, for_update=True)
    if resource is None:
        raise NotFoundError()
    await session.delete(resource)
    await session.flush()
    log.info("resource_deleted", project_id=str(project_id), resource_id=str(resource_id))
