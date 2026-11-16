"""Ownership verification of a project (CU-07; RF-17, RF-18, RF-21; RN-01, RN-02)."""

from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.errors import NotFoundError, UnprocessableError
from hindama.core.ownership import CheckResult, Outcome, OwnershipChecker, published_code
from hindama.models import Project
from hindama.models.enums import VerificationMethod, VerificationStatus
from hindama.repositories import projects as repository

log = structlog.get_logger(__name__)

# RF-21: the exact cause and how to fix it. Fallback texts; the frontend shows its own by `code`.
FAILURES = {
    Outcome.FILE_NOT_FOUND: (
        "No encontramos el archivo de verificación",
        "Publica el archivo en /.well-known/hindama-verificacion.txt de la URL base y vuelve a "
        "intentarlo.",
    ),
    Outcome.CONTENT_MISMATCH: (
        "El archivo no contiene el código",
        "Encontramos el archivo de verificación, pero su contenido no coincide con el código del "
        "proyecto.",
    ),
    Outcome.TXT_MISSING: (
        "No encontramos el registro TXT",
        "Crea el registro TXT con el código del proyecto. Los cambios de DNS pueden tardar en "
        "propagarse.",
    ),
    Outcome.CONNECTION_ERROR: (
        "No pudimos conectarnos",
        "No pudimos conectar con el host o se agotó el tiempo de espera. Revisa que la URL base "
        "responda y tenga un certificado válido.",
    ),
    Outcome.DESTINATION_NOT_ALLOWED: (
        "El destino no está permitido",
        "El host resuelve a una dirección privada, local o reservada, y Hindama no se conecta a "
        "ella.",
    ),
}


class VerificationFailedError(UnprocessableError):
    """422 that still commits: the project stays `pending` (contract, `verifyOwnership`)."""

    def __init__(self, result: CheckResult) -> None:
        title, detail = FAILURES[result.outcome]
        super().__init__(
            f"verification.{result.outcome.value}",
            title,
            detail,
            extensions={"found": result.found},
        )


async def get(session: AsyncSession, project_id: UUID) -> Project:
    project = await repository.get(session, project_id)
    if project is None:
        raise NotFoundError()  # missing or another analyst's: the same answer (RN-02)
    return project


async def verify(
    session: AsyncSession,
    project_id: UUID,
    method: VerificationMethod,
    checker: OwnershipChecker,
) -> tuple[Project, VerificationFailedError | None]:
    """Checks the code on the project's host and records the result.

    The row is locked for the check: a concurrent edit of the base URL waits, so the project is
    never marked verified for a host it no longer has. A failure sends the project back to
    `pending`, also when it was verified (re-checking, RF-20), and is returned, not raised, so the
    caller can answer 422 without rolling that change back.
    """
    project = await session.scalar(
        select(Project).where(Project.id == project_id).with_for_update()
    )
    if project is None:
        raise NotFoundError()
    result = await checker.check(
        method,
        base_url=project.base_url,
        host=project.host,
        code=published_code(project.verification_code),
    )
    if result.outcome == Outcome.VERIFIED:
        project.verification_status = VerificationStatus.VERIFIED
        project.verification_method = method
        project.verified_host = project.host
        project.verified_at = func.now()
        failure = None
        # RF-81 (bitácora) is pending: until then, the log keeps the event.
        log.info("project_verified", project_id=str(project.id), method=method.value)
    else:
        project.verification_status = VerificationStatus.PENDING
        project.verification_method = None
        project.verified_host = None
        project.verified_at = None
        failure = VerificationFailedError(result)
        log.info(
            "project_verification_failed",
            project_id=str(project.id),
            method=method.value,
            outcome=result.outcome.value,
        )
    await session.flush()
    await session.refresh(project)
    return project, failure
