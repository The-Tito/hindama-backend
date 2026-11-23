"""`/projects/{project_id}/identities` (CU-09; RF-28 to RF-34; RN-11).

No response carries the credential: `Identity` has no field for it, only `credential_suffix`.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query, Request, Response, status

from hindama.api.dependencies import Analyst, Audit, DbSession
from hindama.api.projects import MAX_PAGE
from hindama.config import Settings
from hindama.core.credentials import CredentialCipher
from hindama.core.identity_probe import IdentityProber
from hindama.models.enums import (
    AuditAction,
    AuthType,
    BlockStage,
    HttpMethod,
    IdentityRole,
    IdentityStatus,
)
from hindama.repositories.identities import IdentityRow
from hindama.schemas.common import Warning
from hindama.schemas.contracts import OperationRef
from hindama.schemas.identities import (
    Identity,
    IdentityCreate,
    IdentityPage,
    IdentityTest,
    IdentityTestRequest,
    IdentityUpdate,
)
from hindama.services import identities as service
from hindama.services.identities import WARNING_MESSAGES

router = APIRouter(tags=["Identities"])


def get_cipher(request: Request) -> CredentialCipher:
    cipher: CredentialCipher = request.app.state.credential_cipher
    return cipher


def get_prober(request: Request) -> IdentityProber:
    settings: Settings = request.app.state.settings
    prober: IdentityProber | None = getattr(request.app.state, "identity_prober", None)
    return prober or IdentityProber(
        resolver=request.app.state.resolver,
        own_addresses=settings.own_ip_addresses,
        address_policy=getattr(request.app.state, "address_policy", None),
    )


NO_TEST_PREFERENCE = IdentityTestRequest()

Cipher = Annotated[CredentialCipher, Depends(get_cipher)]
Prober = Annotated[IdentityProber, Depends(get_prober)]


def _identity(row: IdentityRow) -> Identity:
    identity = row.identity
    login = row.login_operation
    return Identity(
        id=identity.id,
        name=identity.name,
        role=IdentityRole(identity.role),
        role_label=identity.role_label,
        auth_type=AuthType(identity.auth_type),
        credential_suffix=identity.credential_suffix,
        field_name=identity.field_name,
        login_operation=None
        if login is None
        else OperationRef(id=login.id, method=HttpMethod(login.method), path=login.path),
        status=IdentityStatus(identity.status),
        last_tested_at=identity.last_tested_at,
        last_test_status_code=identity.last_test_status_code,
        resource_count=row.resource_count,
        warnings=[
            Warning(code=code, message=WARNING_MESSAGES[code], location=None)
            for code in service.warnings(row)
        ],
        created_at=identity.created_at,
    )


@router.get(
    "/projects/{project_id}/identities",
    operation_id="listIdentities",
    summary="Identidades del proyecto",
)
async def list_identities(
    project_id: UUID,
    _: Analyst,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> IdentityPage:
    rows, total = await service.list_identities(db, project_id, page, page_size)
    return IdentityPage(
        items=[_identity(row) for row in rows], total=total, page=page, page_size=page_size
    )


@router.post(
    "/projects/{project_id}/identities",
    operation_id="createIdentity",
    summary="Registrar una identidad",
    status_code=status.HTTP_201_CREATED,
)
async def create_identity(
    project_id: UUID,
    body: IdentityCreate,
    _: Analyst,
    db: DbSession,
    cipher: Cipher,
    response: Response,
    audit: Audit,
) -> Identity:
    row = await service.create_identity(
        db,
        cipher,
        project_id,
        name=body.name,
        role=body.role,
        role_label=body.role_label,
        auth_type=body.auth_type,
        credential=body.credential,
        field_name=body.field_name,
        login_operation_id=body.login_operation_id,
    )
    await audit.record(
        AuditAction.IDENTITY_CREATED, project_id=project_id, identity_id=row.identity.id
    )
    response.headers["Location"] = f"/projects/{project_id}/identities/{row.identity.id}"
    return _identity(row)


@router.patch(
    "/projects/{project_id}/identities/{identity_id}",
    operation_id="updateIdentity",
    summary="Editar una identidad",
)
async def update_identity(
    project_id: UUID,
    identity_id: UUID,
    body: IdentityUpdate,
    _: Analyst,
    db: DbSession,
    cipher: Cipher,
) -> Identity:
    # Not model_dump: the credential stays a model (its shape tells the kind) and is never copied
    # into a plain dict that could end up in a log.
    changes = {name: getattr(body, name) for name in body.model_fields_set}
    return _identity(await service.update_identity(db, cipher, project_id, identity_id, changes))


@router.delete(
    "/projects/{project_id}/identities/{identity_id}",
    operation_id="deleteIdentity",
    summary="Eliminar una identidad",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_identity(
    project_id: UUID, identity_id: UUID, user: Analyst, db: DbSession, audit: Audit
) -> Response:
    await service.delete_identity(db, user, project_id, identity_id)
    await audit.record(AuditAction.IDENTITY_DELETED, project_id=project_id, identity_id=identity_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/projects/{project_id}/identities/{identity_id}/test",
    operation_id="testIdentity",
    summary="Probar la credencial de una identidad",
)
async def test_identity(
    project_id: UUID,
    identity_id: UUID,
    _: Analyst,
    db: DbSession,
    cipher: Cipher,
    prober: Prober,
    audit: Audit,
    # Optional body, never JSON `null` (contract): absent means "let the system choose".
    body: Annotated[IdentityTestRequest, Body()] = NO_TEST_PREFERENCE,
) -> IdentityTest:
    async with audit.blocks(BlockStage.IDENTITY_TEST, project_id):
        outcome = await service.test_identity(
            db,
            cipher,
            prober,
            project_id,
            identity_id,
            body.operation_id,
        )
    operation = outcome.operation
    result = outcome.result
    return IdentityTest(
        succeeded=result.succeeded,
        status_code=result.status_code,
        failure=None if result.failure is None else result.failure.value,
        operation=OperationRef(
            id=operation.id, method=HttpMethod(operation.method), path=operation.path
        ),
        tested_at=outcome.tested_at,
    )
