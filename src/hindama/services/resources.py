"""Resources by identity (F-06, CU-10; RF-36 to RF-38).

The object access module (RF-56) asks for another identity's object with each identity: it needs
to know whose each object is. They are registered by hand (`source: manual`, confirmed) or
discovered by calling the contract's listings as each identity (`source: discovered`, unconfirmed
until the analyst confirms them: CU-10 step 5).
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.credentials import CredentialCipher, CredentialUnreadableError
from hindama.core.errors import ConflictError, FieldIssue, NotFoundError, UnprocessableError
from hindama.core.resource_discovery import (
    ListOperation,
    ResourceDiscoverer,
    Searcher,
    array_location,
    needs_document,
    resource_type,
)
from hindama.models import Identity, Project, Resource
from hindama.models.enums import AuthType, ResourceSource
from hindama.repositories import identities as identities_repository
from hindama.repositories import projects as projects_repository
from hindama.repositories import resources as repository
from hindama.services.identities import login_request, stored_document
from hindama.services.projects import is_verified

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


# ------------------------------------------------------------------ discovery (RF-36)


@dataclass(frozen=True, slots=True)
class IdentityDiscovery:
    identity_id: UUID
    found: int
    created: int
    owned_by_other: int
    failure: str | None


@dataclass(frozen=True, slots=True)
class Discovery:
    created: list[Resource]
    identities: list[IdentityDiscovery]
    requests_sent: int
    truncated: bool


def _chosen(
    identities: list[Identity], given: list[UUID] | None, anonymous: set[UUID]
) -> list[Identity]:
    """The identities that discover, in the order given; all of them without `identity_ids`."""
    if given is None:
        return identities
    by_id = {identity.id: identity for identity in identities}
    for index, identity_id in enumerate(given):
        if identity_id in anonymous:
            raise UnprocessableError(
                "resource.anonymous_owner",
                "La identidad anónima no tiene recursos",
                "Quita la identidad anónima: no envía credenciales, así que no tiene recursos.",
                [FieldIssue(f"identity_ids.{index}", "resource.anonymous_owner", "Es la anónima.")],
            )
        if identity_id not in by_id:
            raise UnprocessableError(
                "identity.not_found",
                "Identidad desconocida",
                "Una de las identidades no existe en el proyecto o fue eliminada.",
                [
                    FieldIssue(
                        f"identity_ids.{index}",
                        "identity.not_found",
                        "No es una identidad vigente.",
                    )
                ],
            )
    return [by_id[identity_id] for identity_id in given]


async def _listings(session: AsyncSession, project_id: UUID, base_url: str) -> list[ListOperation]:
    documents: dict[UUID, Any] = {}
    result = []
    for operation, description, contract_id in await repository.get_operations_without_parameters(
        session, project_id
    ):
        kind = resource_type(operation.path)
        responses = description.schemas.get("responses") or {}
        if kind is None or not isinstance(responses, dict):
            continue
        document = None
        if needs_document(responses):
            if contract_id not in documents:
                documents[contract_id] = await stored_document(session, contract_id)
            document = documents[contract_id]
        is_listing, array_field = array_location(responses, document)
        if is_listing:
            result.append(ListOperation(base_url.rstrip("/") + operation.path, kind, array_field))
    return result


async def _searcher(
    session: AsyncSession, cipher: CredentialCipher, project: Project, identity: Identity
) -> Searcher:
    kind = AuthType(identity.auth_type)
    login = None
    if kind == AuthType.LOGIN and identity.login_operation_id is not None:
        login = await login_request(session, project, identity.login_operation_id)
    try:
        if identity.encrypted_credential is None:  # the CHECK constraints make it impossible
            raise CredentialUnreadableError()
        credential = cipher.decrypt(identity.id, identity.encrypted_credential)
    except CredentialUnreadableError:
        # A lost or rotated-out key, or a tampered row: an internal fault, never the analyst's.
        log.error("identity_credential_unreadable", identity_id=str(identity.id))
        raise
    return Searcher(identity.id, kind, credential, identity.field_name, login)


async def discover_resources(
    session: AsyncSession,
    cipher: CredentialCipher,
    discoverer: ResourceDiscoverer,
    project_id: UUID,
    identity_ids: list[UUID] | None,
) -> Discovery:
    """RF-36. Synchronous, with the project locked: no run starts meanwhile (RN-07), and two
    discoveries cannot both take the same object for different identities."""
    project = await identities_repository.lock_project(session, project_id)
    if project is None:
        raise NotFoundError()
    if not is_verified(project):
        raise ConflictError(
            "project.not_verified",
            "Proyecto sin verificar",
            "Verifica la propiedad del dominio antes de enviar peticiones a tu API.",
        )
    if await projects_repository.has_active_run(session, project_id):
        raise ConflictError(
            "project.active_run",
            "Hay una ejecución activa",
            "Espera a que termine la ejecución o cancélala antes de descubrir recursos.",
        )
    live = await repository.searchers(session, project_id)
    anonymous = set()
    if identity_ids is not None:
        for identity_id in identity_ids:
            identity = await identities_repository.get(session, project_id, identity_id)
            if identity is not None and identity.auth_type == AuthType.NONE:
                anonymous.add(identity_id)
    identities = _chosen(live, identity_ids, anonymous)
    listings = await _listings(session, project_id, project.base_url)
    if not listings:
        raise UnprocessableError(
            "resource.no_list_operations",
            "No hay operaciones de listado",
            "El contrato vigente no tiene operaciones GET sin parámetros de ruta que devuelvan "
            "un arreglo; registra los recursos a mano.",
            [FieldIssue(None, "resource.no_list_operations", "Sin operaciones de listado.")],
        )
    searchers = [await _searcher(session, cipher, project, identity) for identity in identities]
    outcome = await discoverer.discover(project.host, listings, searchers)

    owners = await repository.owners(
        session, project_id, {kind for f in outcome.identities for kind, _ in f.found}
    )
    created: list[Resource] = []
    summaries = []
    for findings in outcome.identities:
        new = taken = 0
        for kind, value in findings.found:
            owner = owners.get((kind, value))
            if owner == findings.identity_id:
                continue  # already its own: unchanged
            if owner is not None:
                taken += 1  # an object has a single owner
                continue
            resource = Resource(
                project_id=project_id,
                identity_id=findings.identity_id,
                resource_type=kind,
                value=value,
                source=ResourceSource.DISCOVERED,
                confirmed=False,
            )
            session.add(resource)
            owners[(kind, value)] = findings.identity_id
            created.append(resource)
            new += 1
        summaries.append(
            IdentityDiscovery(
                identity_id=findings.identity_id,
                found=len(findings.found),
                created=new,
                owned_by_other=taken,
                failure=None if findings.failure is None else findings.failure.value,
            )
        )
    await session.flush()
    for resource in created:
        await session.refresh(resource, ["created_at"])
    created.sort(key=lambda r: (r.resource_type, r.value, r.id))
    log.info(
        "resources_discovered",
        project_id=str(project_id),
        identities=len(identities),
        created=len(created),
        requests_sent=outcome.requests_sent,
        truncated=outcome.truncated,
    )
    return Discovery(created, summaries, outcome.requests_sent, outcome.truncated)
