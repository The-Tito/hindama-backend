"""`GET /me` (getMe) and `POST /me/terms` (acceptTerms): CU-02, RF-16, RN-12."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from hindama.api.dependencies import AnyUser, DbSession
from hindama.config import Settings
from hindama.core.cognito import Profile, ProfileClient
from hindama.schemas.accounts import Me, TermsAcceptance, TermsStatus
from hindama.services import accounts as accounts_service
from hindama.services.accounts import Account

router = APIRouter(tags=["Account"])


async def get_profile(request: Request) -> Profile:
    """Name and email from Cognito, with the token the middleware already validated."""
    client: ProfileClient = request.app.state.profiles
    _, _, token = request.headers["authorization"].partition(" ")
    return await client.get(token.strip())


def get_terms_version(request: Request) -> str:
    settings: Settings = request.app.state.settings
    return settings.terms_version


CallerProfile = Annotated[Profile, Depends(get_profile)]
TermsVersion = Annotated[str, Depends(get_terms_version)]


def _me(account: Account) -> Me:
    terms = account.terms
    return Me(
        id=account.user.id,
        name=account.profile.name,
        email=account.profile.email,
        role=account.user.role,
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
