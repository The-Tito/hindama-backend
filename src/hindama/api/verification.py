"""`/projects/{project_id}/verification` (CU-07; RF-17 to RF-21; RN-01)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from hindama.api.dependencies import Analyst, Audit, DbSession
from hindama.api.problems import app_error_response
from hindama.core.ownership import OwnershipChecker, dns_name, file_url, published_code
from hindama.models import Project
from hindama.models.enums import AuditAction, BlockStage, VerificationMethod, VerificationStatus
from hindama.schemas.verification import (
    DnsInstructions,
    FileInstructions,
    Verification,
    VerificationRequest,
)
from hindama.services import verification as service

router = APIRouter(tags=["Verification"])


def get_checker(request: Request) -> OwnershipChecker:
    checker: OwnershipChecker = request.app.state.ownership_checker
    return checker


Checker = Annotated[OwnershipChecker, Depends(get_checker)]


def _verification(project: Project) -> Verification:
    code = published_code(project.verification_code)
    return Verification(
        status=VerificationStatus(project.verification_status),
        host=project.host,
        code=code,
        method=None
        if project.verification_method is None
        else VerificationMethod(project.verification_method),
        verified_at=project.verified_at,
        file=FileInstructions(url=file_url(project.base_url), content=code),
        dns=DnsInstructions(name=dns_name(project.host), type="TXT", value=code),
    )


@router.get(
    "/projects/{project_id}/verification",
    operation_id="getVerification",
    summary="Instrucciones y estado de la verificación",
)
async def get_verification(project_id: UUID, _: Analyst, db: DbSession) -> Verification:
    return _verification(await service.get(db, project_id))


@router.post(
    "/projects/{project_id}/verification",
    operation_id="verifyOwnership",
    summary="Comprobar la propiedad",
    response_model=Verification,
)
async def verify_ownership(
    project_id: UUID,
    body: VerificationRequest,
    _: Analyst,
    db: DbSession,
    checker: Checker,
    audit: Audit,
) -> Verification | JSONResponse:
    async with audit.blocks(BlockStage.VERIFICATION, project_id):
        project, failure = await service.verify(db, project_id, body.method, checker)
    if failure is not None:
        # Returned, not raised: the session commits the project back to `pending`.
        return app_error_response(failure)
    await audit.record(
        AuditAction.PROJECT_VERIFIED,
        project_id=project_id,
        host=project.host,
        verification_method=body.method,
    )
    return _verification(project)
