"""`/projects/{project_id}/resources` (CU-10; RF-36 to RF-38)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query, Request, Response, status
from pydantic import MISSING

from hindama.api.dependencies import Analyst, DbSession
from hindama.api.identities import Cipher
from hindama.api.projects import MAX_PAGE
from hindama.config import Settings
from hindama.core.resource_discovery import ResourceDiscoverer
from hindama.models import Resource as ResourceRow
from hindama.schemas.common import SINGLE_LINE
from hindama.schemas.resources import (
    DiscoveryIdentityResult,
    Resource,
    ResourceCreate,
    ResourceDiscovery,
    ResourceDiscoveryRequest,
    ResourcePage,
    ResourceUpdate,
)
from hindama.services import resources as service

router = APIRouter(tags=["Resources"])


def get_discoverer(request: Request) -> ResourceDiscoverer:
    """Tests put one that may reach a local server in `app.state.resource_discoverer`."""
    settings: Settings = request.app.state.settings
    discoverer: ResourceDiscoverer | None = getattr(request.app.state, "resource_discoverer", None)
    return discoverer or ResourceDiscoverer(
        resolver=request.app.state.resolver,
        own_addresses=settings.own_ip_addresses,
        address_policy=getattr(request.app.state, "address_policy", None),
    )


Discoverer = Annotated[ResourceDiscoverer, Depends(get_discoverer)]
ALL_IDENTITIES = ResourceDiscoveryRequest()


def _resource(row: ResourceRow) -> Resource:
    return Resource(
        id=row.id,
        identity_id=row.identity_id,
        resource_type=row.resource_type,
        value=row.value,
        source=row.source,  # CHECK constraint: discovered or manual
        confirmed=row.confirmed,
        created_at=row.created_at,
    )


@router.get(
    "/projects/{project_id}/resources",
    operation_id="listResources",
    summary="Recursos por identidad",
)
async def list_resources(
    project_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    identity_id: UUID | None = None,
    resource_type: Annotated[
        str | None, Query(min_length=1, max_length=100, pattern=SINGLE_LINE)
    ] = None,
) -> ResourcePage:
    rows, total = await service.list_resources(
        db,
        project_id,
        identity_id=identity_id,
        resource_type=resource_type,
        page=page,
        page_size=page_size,
    )
    return ResourcePage(
        items=[_resource(row) for row in rows], total=total, page=page, page_size=page_size
    )


@router.post(
    "/projects/{project_id}/resources",
    operation_id="createResource",
    summary="Registrar un recurso a mano",
    status_code=status.HTTP_201_CREATED,
)
async def create_resource(
    project_id: UUID, body: ResourceCreate, _: Analyst, db: DbSession, response: Response
) -> Resource:
    row = await service.create_resource(
        db,
        project_id,
        identity_id=body.identity_id,
        resource_type=body.resource_type,
        value=body.value,
    )
    response.headers["Location"] = f"/projects/{project_id}/resources/{row.id}"
    return _resource(row)


@router.post(
    "/projects/{project_id}/resources/discovery",
    operation_id="discoverResources",
    summary="Descubrir recursos por identidad",
)
async def discover_resources(
    project_id: UUID,
    _: Analyst,
    db: DbSession,
    cipher: Cipher,
    discoverer: Discoverer,
    # Optional body, never JSON `null` (contract): absent means every identity.
    body: Annotated[ResourceDiscoveryRequest, Body()] = ALL_IDENTITIES,
) -> ResourceDiscovery:
    given = body.identity_ids
    result = await service.discover_resources(
        db, cipher, discoverer, project_id, None if given is MISSING else given
    )
    return ResourceDiscovery(
        created=[_resource(row) for row in result.created],
        identities=[
            DiscoveryIdentityResult(
                identity_id=item.identity_id,
                found=item.found,
                created=item.created,
                owned_by_other=item.owned_by_other,
                failure=item.failure,
            )
            for item in result.identities
        ],
        requests_sent=result.requests_sent,
        truncated=result.truncated,
    )


# `:uuid`: `/resources/discovery` must not reach these routes; another method there is a 405.
@router.patch(
    "/projects/{project_id}/resources/{resource_id:uuid}",
    operation_id="updateResource",
    summary="Editar o confirmar un recurso",
)
async def update_resource(
    project_id: UUID, resource_id: UUID, body: ResourceUpdate, _: Analyst, db: DbSession
) -> Resource:
    changes = {name: getattr(body, name) for name in body.model_fields_set}
    return _resource(await service.update_resource(db, project_id, resource_id, changes))


@router.delete(
    "/projects/{project_id}/resources/{resource_id:uuid}",
    operation_id="deleteResource",
    summary="Eliminar un recurso",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_resource(
    project_id: UUID, resource_id: UUID, _: Analyst, db: DbSession
) -> Response:
    await service.delete_resource(db, project_id, resource_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
