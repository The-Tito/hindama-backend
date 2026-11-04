"""Projects (F-02): CU-05 create, CU-06 list, dashboard, edit and delete."""

import secrets
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.auth import CurrentUser
from hindama.core.destinations import (
    CheckedUrl,
    InvalidUrlError,
    IPAddress,
    Resolver,
    UrlProblem,
    check_base_url,
)
from hindama.core.errors import (
    ConflictError,
    FieldIssue,
    ForbiddenError,
    NotFoundError,
    UnprocessableError,
)
from hindama.models import ContractVersion, Project, Run
from hindama.models.enums import DailyMetricName, Module, Severity, VerificationStatus
from hindama.repositories import metrics, users
from hindama.repositories import projects as repository
from hindama.repositories.projects import Configuration, ProjectRow, Sort

# Risk of each module (RN-05): medium and high need a confirmation on every run.
MODULE_RISK = {
    Module.AUTHENTICATION: "low",
    Module.CONFIGURATION: "low",
    Module.OBJECT_ACCESS: "low",
    Module.FUNCTION_ACCESS: "low",
    Module.PROPERTY_ACCESS: "medium",
    Module.RESOURCE_CONSUMPTION: "high",
    Module.SQL_INJECTION: "high",
}
# Order of `missing` in the contract (ModuleAvailability).
REQUIREMENTS = (
    "project_not_verified",
    "no_contract",
    "insufficient_identities",
    "no_admin_identity",
    "no_resources",
    "policy_unconfirmed",
)

_URL_MESSAGES = {
    UrlProblem.INVALID_FORMAT: (
        "La URL no es válida",
        "Escribe una URL completa, sin usuario, contraseña ni fragmento.",
        "Formato de URL no válido.",
    ),
    UrlProblem.SCHEME_NOT_ALLOWED: (
        "Esquema no permitido",
        "La URL base debe empezar con http:// o https://.",
        "Solo se permiten http y https.",
    ),
    UrlProblem.DESTINATION_NOT_ALLOWED: (
        "La URL apunta a un destino no permitido",
        "La URL base apunta a una dirección privada, local o reservada. Usa una dirección pública "
        "de tu API.",
        "Apunta a una dirección no permitida.",
    ),
}

WARNING_MESSAGES = {
    "url.no_tls": "La URL usa HTTP; el tráfico y las credenciales de prueba viajarán sin cifrar.",
    "url.unresolved": (
        "El host todavía no resuelve en DNS. Podrás verificar el proyecto cuando resuelva."
    ),
    "project.verification_lost": (
        "Cambió el host de la URL base: el proyecto volvió a «Pendiente de verificación»."
    ),
}


@dataclass(frozen=True, slots=True)
class UrlPolicy:
    resolver: Resolver
    own_addresses: tuple[IPAddress, ...] = ()


@dataclass(frozen=True, slots=True)
class Availability:
    module: Module
    risk: str
    missing: list[str]

    @property
    def available(self) -> bool:
        return not self.missing


@dataclass(slots=True)
class Dashboard:
    project: Project
    concluded: bool
    current_contract: ContractVersion | None
    last_run: Run | None
    open_findings: dict[Severity, int]
    modules: list[Availability]
    warnings: list[str] = field(default_factory=list)  # codes; persistent ones included


async def _checked_url(raw: str, policy: UrlPolicy) -> CheckedUrl:
    try:
        return await check_base_url(raw, policy.resolver, policy.own_addresses)
    except InvalidUrlError as error:
        title, detail, message = _URL_MESSAGES[error.problem]
        raise UnprocessableError(
            error.problem.value,
            title,
            detail,
            [FieldIssue("base_url", error.problem.value, message)],
        ) from error


def module_availability(
    verified: bool, has_contract: bool, config: Configuration
) -> list[Availability]:
    """RF-45: what each module still needs, in the catalog order.

    - Object access (RF-56): two authenticated identities, both with resources, and an operation
      whose confirmed policy requires ownership.
    - Function access (RF-57): an administrator identity and an operation confirmed as admin only;
      the non-administrator side can be any other identity, including the anonymous one.
    - Property access (RF-58): at least one authenticated identity.
    """
    common = {
        "project_not_verified": not verified,
        "no_contract": not has_contract,
    }
    needs = {
        Module.AUTHENTICATION: {**common},
        Module.CONFIGURATION: {"project_not_verified": not verified},
        Module.OBJECT_ACCESS: {
            **common,
            "insufficient_identities": config.authenticated_identities < 2,
            "no_resources": config.identities_with_resources < 2,
            "policy_unconfirmed": not config.has_ownership_policy,
        },
        Module.FUNCTION_ACCESS: {
            **common,
            "no_admin_identity": not config.has_admin_identity,
            "policy_unconfirmed": not config.has_admin_only_policy,
        },
        Module.PROPERTY_ACCESS: {
            **common,
            "insufficient_identities": config.authenticated_identities < 1,
        },
        Module.RESOURCE_CONSUMPTION: {**common},
        Module.SQL_INJECTION: {**common},
    }
    return [
        Availability(
            module=module,
            risk=MODULE_RISK[module],
            missing=[r for r in REQUIREMENTS if needs[module].get(r, False)],
        )
        for module in Module
    ]


def persistent_warnings(project: Project) -> list[str]:
    return ["url.no_tls"] if project.base_url.startswith("http://") else []


async def dashboard(
    session: AsyncSession, project_id: UUID, momentary: list[str] | None = None
) -> Dashboard:
    row = await repository.get_row(session, project_id)
    if row is None:
        raise NotFoundError()
    return await _dashboard(session, row, momentary or [])


async def _dashboard(session: AsyncSession, row: ProjectRow, momentary: list[str]) -> Dashboard:
    project = row.project
    contract = await repository.current_contract(session, project.id)
    config = await repository.configuration(session, project.id)
    verified = project.verification_status == VerificationStatus.VERIFIED
    return Dashboard(
        project=project,
        concluded=row.concluded,
        current_contract=contract,
        last_run=await repository.last_run(session, project.id),
        open_findings=await repository.open_findings_by_severity(session, project.id),
        modules=module_availability(verified, contract is not None, config),
        warnings=persistent_warnings(project) + momentary,
    )


async def list_projects(
    session: AsyncSession, sort: Sort, page: int, page_size: int
) -> tuple[list[ProjectRow], int]:
    return await repository.list_page(session, sort, page, page_size)


async def create_project(
    session: AsyncSession,
    user: CurrentUser,
    *,
    name: str,
    description: str | None,
    base_url: str,
    terms_version: str,
    url_policy: UrlPolicy,
) -> Dashboard:
    """CU-05. Requires the terms in force (RN-12) before anything else is checked."""
    account = await users.get(session, user.id)
    if account.terms_version != terms_version:
        raise ForbiddenError(
            "terms.not_accepted",
            "Faltan los términos de uso",
            "Acepta los términos de uso responsable antes de crear tu primer proyecto.",
        )
    checked = await _checked_url(base_url, url_policy)
    project = await repository.create(
        session,
        owner_id=user.id,
        name=name,
        description=description,
        base_url=checked.parsed.url,
        host=checked.parsed.host,
        verification_code=secrets.token_hex(16),  # RF-17: random and unique, not secret
    )
    await metrics.increment_daily(session, DailyMetricName.PROJECTS_CREATED)
    return await dashboard(session, project.id, [] if checked.resolved else ["url.unresolved"])


async def update_project(
    session: AsyncSession, project_id: UUID, changes: dict[str, object], url_policy: UrlPolicy
) -> Dashboard:
    """RF-13. A new host sends the project back to pending verification."""
    project = await repository.get(session, project_id)
    if project is None:
        raise NotFoundError()
    if not changes:
        raise UnprocessableError(
            "validation.failed",
            "Datos inválidos",
            "Envía al menos un campo para modificar.",
            [FieldIssue(None, "validation.required", "Envía al menos un campo.")],
        )
    momentary: list[str] = []
    if "name" in changes:
        project.name = str(changes["name"])
    if "description" in changes:
        description = changes["description"]
        project.description = None if description is None else str(description)
    if "base_url" in changes:
        checked = await _checked_url(str(changes["base_url"]), url_policy)
        if not checked.resolved:
            momentary.append("url.unresolved")
        if checked.parsed.host != project.host:
            if project.verification_status == VerificationStatus.VERIFIED:
                momentary.append("project.verification_lost")
            project.verification_status = VerificationStatus.PENDING
            project.verification_method = None
            project.verified_at = None
            project.verified_host = None
            project.host = checked.parsed.host
        project.base_url = checked.parsed.url
    await session.flush()
    await session.refresh(project)
    return await dashboard(session, project.id, momentary)


async def delete_project(session: AsyncSession, project_id: UUID, confirmation: str) -> None:
    """RF-14, CU-06 A2. The written name must match exactly."""
    project = await repository.get(session, project_id)
    if project is None:
        raise NotFoundError()
    if confirmation != project.name:
        raise UnprocessableError(
            "project.confirmation_mismatch",
            "El nombre no coincide",
            "Escribe el nombre exacto del proyecto para confirmar que quieres eliminarlo.",
            [FieldIssue("confirmation", "project.confirmation_mismatch", "No coincide.")],
        )
    if await repository.has_active_run(session, project_id):
        raise ConflictError(
            "project.active_run",
            "Hay una ejecución activa",
            "Cancela la ejecución en curso antes de eliminar el proyecto.",
        )
    await repository.delete_project(session, project_id)
