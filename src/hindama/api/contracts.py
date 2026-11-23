"""`/projects/{project_id}/contracts` and `/operations` (CU-08; RF-22 to RF-27)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, File, Form, Query, Response, UploadFile, status

from hindama.api.dependencies import Analyst, Audit, DbSession
from hindama.api.projects import MAX_PAGE, Destinations
from hindama.core.openapi_import import is_login_candidate
from hindama.models import Operation as OperationRow
from hindama.models import OperationVersion
from hindama.models.base import MAX_CONTRACT_BYTES
from hindama.models.enums import BlockStage, HttpMethod, Policy
from hindama.schemas.common import Warning
from hindama.schemas.contracts import (
    ContractChanges,
    ContractPage,
    ContractVersion,
    DeclaredSecurity,
    Operation,
    OperationPage,
    OperationRef,
    Parameter,
    RequestBody,
    ResourceParameter,
)
from hindama.schemas.projects import ContractVersionSummary
from hindama.services import contracts as service
from hindama.services.contracts import ContractView, Upload

router = APIRouter(tags=["Contracts"])


def _contract(view: ContractView) -> ContractVersion:
    version = view.version
    changes = view.changes

    def refs(items: list[service.OperationRef]) -> list[OperationRef]:
        return [OperationRef(id=r.id, method=HttpMethod(r.method), path=r.path) for r in items]

    return ContractVersion(
        id=version.id,
        number=version.number,
        source=version.source,
        openapi_version=version.openapi_version,
        operation_count=version.operation_count,
        imported_at=version.imported_at,
        source_url=version.source_url,
        file_name=version.file_name,
        format=version.format,
        api_title=version.api_title,
        sha256=version.sha256,
        is_current=view.is_current,
        warnings=[Warning(**warning) for warning in view.warnings],
        changes=None
        if changes is None
        else ContractChanges(
            previous_version=changes.previous_version,
            added=refs(changes.added),
            modified=refs(changes.modified),
            removed=refs(changes.removed),
        ),
    )


@router.get(
    "/projects/{project_id}/contracts",
    operation_id="listContracts",
    summary="Versiones del contrato",
)
async def list_contracts(
    project_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> ContractPage:
    versions, total = await service.list_contracts(db, project_id, page, page_size)
    return ContractPage(
        items=[
            ContractVersionSummary(
                id=v.id,
                number=v.number,
                source=v.source,
                openapi_version=v.openapi_version,
                operation_count=v.operation_count,
                imported_at=v.imported_at,
            )
            for v in versions
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/projects/{project_id}/contracts",
    operation_id="importContract",
    summary="Importar una versión del contrato",
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {
            "model": ContractVersion,
            "description": "El documento es idéntico a la versión vigente.",
        }
    },
)
async def import_contract(
    project_id: UUID,
    user: Analyst,
    db: DbSession,
    response: Response,
    destinations: Destinations,
    audit: Audit,
    file: Annotated[UploadFile | None, File()] = None,
    url: Annotated[str | None, Form(max_length=2048)] = None,
) -> ContractVersion:
    upload = None
    if file is not None:
        # The middleware already capped the body; one byte more tells an oversized file apart.
        content = await file.read(MAX_CONTRACT_BYTES + 1)
        upload = Upload(content=content, file_name=file.filename)
    async with audit.blocks(BlockStage.CONTRACT_IMPORT, project_id):
        view, created = await service.import_contract(
            db, project_id, user.id, upload=upload, url=url, url_policy=destinations
        )
    if created:
        response.headers["Location"] = f"/projects/{project_id}/contracts/{view.version.id}"
    else:
        response.status_code = status.HTTP_200_OK
    return _contract(view)


@router.get(
    "/projects/{project_id}/contracts/{contract_id}",
    operation_id="getContract",
    summary="Una versión del contrato",
)
async def get_contract(
    project_id: UUID, contract_id: UUID, _: Analyst, db: DbSession
) -> ContractVersion:
    return _contract(await service.get_contract(db, project_id, contract_id))


def operation_view(row: OperationRow, version: OperationVersion) -> Operation:
    body = version.request_body
    return Operation(
        id=row.id,
        method=HttpMethod(row.method),
        path=version.path,
        operation_id=version.openapi_operation_id,
        summary=version.summary,
        tags=list(version.tags),
        parameters=[
            Parameter(
                name=p["name"], location=p["location"], required=p["required"], type=p["type"]
            )
            for p in version.parameters
        ],
        body=None
        if body is None
        else RequestBody(required=body["required"], content_types=body["content_types"]),
        security=[DeclaredSecurity(**s) for s in version.security],
        retired_at=row.retired_at,
        suggested_policy=None if row.suggested_policy is None else Policy(row.suggested_policy),
        policy=None if row.policy is None else Policy(row.policy),
        owner_field=row.owner_field,
        confirmed_at=row.confirmed_at,
        modified_at=row.modified_at,
        resource_parameters=[ResourceParameter(**p) for p in row.resource_parameters],
        is_login_candidate=is_login_candidate(row.method, version.path),
    )


@router.get(
    "/projects/{project_id}/operations",
    operation_id="listOperations",
    summary="Operaciones del proyecto",
)
async def list_operations(
    project_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 100,
    include_retired: bool = False,
    method: HttpMethod | None = None,
) -> OperationPage:
    rows, total = await service.list_operations(
        db,
        project_id,
        include_retired=include_retired,
        method=None if method is None else method.value,
        page=page,
        page_size=page_size,
    )
    return OperationPage(
        items=[operation_view(row, version) for row, version in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
