"""`GET /me` (getMe), `POST /me/terms` (acceptTerms) and `DELETE /me` (deleteAccount).

CU-02, CU-25, RF-16, RF-88, RN-12.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status

from hindama.api.dependencies import (
    Analyst,
    AnyUser,
    Audit,
    CallerProfile,
    DbSession,
    access_token,
    get_profile_client,
)
from hindama.config import Settings
from hindama.core.errors import AppError, ServiceUnavailableError
from hindama.models.enums import AuditAction
from hindama.schemas.accounts import Me, TermsAcceptance, TermsStatus
from hindama.schemas.common import SINGLE_LINE
from hindama.services import accounts as accounts_service
from hindama.services.accounts import Account

router = APIRouter(tags=["Account"])


def get_terms_version(request: Request) -> str:
    settings: Settings = request.app.state.settings
    return settings.terms_version


TermsVersion = Annotated[str, Depends(get_terms_version)]


def _me(account: Account) -> Me:
    terms = account.terms
    return Me(
        id=account.user.id,
        name=account.profile.name,
        email=account.profile.email,
        role=account.user.role,
        mfa_enabled=account.profile.mfa_enabled,
        terms=TermsStatus(
            current_version=terms.current_version,
            accepted_version=terms.accepted_version,
            accepted_at=terms.accepted_at,
            acceptance_required=terms.acceptance_required,
        ),
    )


@router.get("/me", operation_id="getMe", summary="Usuario de la sesión")
async def get_me(
    user: AnyUser, db: DbSession, profile: CallerProfile, current_version: TermsVersion
) -> Me:
    return _me(await accounts_service.get_account(db, user, profile, current_version))


@router.post(
    "/me/terms", operation_id="acceptTerms", summary="Aceptar los términos de uso responsable"
)
async def accept_terms(
    body: TermsAcceptance,
    user: AnyUser,
    db: DbSession,
    profile: CallerProfile,
    current_version: TermsVersion,
) -> Me:
    account = await accounts_service.accept_terms(db, user, profile, body.version, current_version)
    return _me(account)


@router.delete(
    "/me",
    operation_id="deleteAccount",
    summary="Eliminar la cuenta",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_account(
    request: Request,
    confirmation: Annotated[str, Query(min_length=1, max_length=254, pattern=SINGLE_LINE)],
    user: Analyst,
    db: DbSession,
    audit: Audit,
    profile: CallerProfile,
) -> Response:
    """CU-25. The data goes first, in one transaction; the Cognito account after (modelo.md 7.2).

    If Cognito fails, the data is already gone: the analyst repeats the request, which enters an
    empty account and finishes the deletion (CU-25 E3).
    """
    await accounts_service.delete_account(db, user, profile, confirmation)
    await audit.record(AuditAction.ACCOUNT_DELETED)
    await db.commit()
    try:
        await get_profile_client(request).delete(access_token(request))
    except ServiceUnavailableError as error:
        raise AppError(
            code="account.deletion_incomplete",
            title="Baja incompleta",
            detail="Tus datos ya se borraron, pero no se pudo cerrar tu cuenta. Repite la baja.",
            status=503,
        ) from error
    return Response(status_code=status.HTTP_204_NO_CONTENT)
