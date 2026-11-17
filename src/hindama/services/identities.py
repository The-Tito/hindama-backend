"""Test identities (F-05, CU-09; RF-28 to RF-34; RN-01, RN-11).

The credential is encrypted before it reaches the database, with the identity's id as associated
data (ADR-007), and leaves this module only towards the analyst's API, through the SSRF guard.
"""

import asyncio
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.auth import CurrentUser
from hindama.core.credentials import Credential, CredentialCipher, CredentialUnreadableError
from hindama.core.errors import ConflictError, FieldIssue, NotFoundError, UnprocessableError
from hindama.core.identity_probe import (
    IdentityProber,
    LoginRequest,
    Probe,
    ProbeResult,
    login_fields,
)
from hindama.core.openapi_import import ContractError, read_document
from hindama.models import Identity, Operation, Project
from hindama.models.base import new_id
from hindama.models.enums import AuthType, IdentityStatus, VerificationStatus
from hindama.repositories import identities as repository
from hindama.repositories import projects as projects_repository
from hindama.repositories.identities import IdentityRow
from hindama.schemas.identities import LoginCredential, TokenCredential, ValueCredential

log = structlog.get_logger(__name__)

MAX_IDENTITIES = 20  # per project, the anonymous one included (convenciones.md)
# Headers the platform controls: an identity cannot replace them (`identity.field_name_reserved`).
RESERVED_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "expect",
        "proxy-authorization",
        "proxy-connection",
        "cookie",
        "user-agent",
    }
)
DOCUMENT_TIMEOUT_SECONDS = 10.0
MAX_REF_HOPS = 16

WARNING_MESSAGES = {
    "identity.no_resources": (
        "La identidad no tiene recursos: el módulo de acceso a objetos no podrá probarla."
    ),
}

_SHAPES: dict[AuthType, type[Any]] = {
    AuthType.LOGIN: LoginCredential,
    AuthType.BEARER: TokenCredential,
    AuthType.COOKIE: ValueCredential,
    AuthType.HEADER: ValueCredential,
}


def _invalid(code: str, field: str, title: str, detail: str, message: str) -> UnprocessableError:
    return UnprocessableError(code, title, detail, [FieldIssue(field, code, message)])


def _anonymous() -> ConflictError:
    return ConflictError(
        "identity.anonymous",
        "La identidad anónima no se modifica",
        "La identidad anónima siempre existe y no tiene credencial: no se edita, borra ni prueba.",
    )


def _credential(auth_type: AuthType, given: Any) -> Credential:
    if not isinstance(given, _SHAPES[auth_type]):
        raise _invalid(
            "identity.credential_mismatch",
            "credential",
            "La credencial no corresponde a la forma de autenticación",
            "Login lleva usuario y contraseña; Bearer, un token; cookie y cabecera, un valor.",
            "No corresponde a auth_type.",
        )
    if isinstance(given, LoginCredential):
        return Credential(username=given.username, password=given.password)
    if isinstance(given, TokenCredential):
        return Credential(token=given.token)
    return Credential(value=given.value)


def _check_field_name(auth_type: AuthType, field_name: str | None) -> str | None:
    if auth_type not in (AuthType.COOKIE, AuthType.HEADER):
        return None  # meaningless for login and bearer: not kept
    if field_name is None:
        raise _invalid(
            "identity.field_name_required",
            "field_name",
            "Falta el nombre",
            "Indica el nombre de la cookie o de la cabecera.",
            "Obligatorio con cookie y header.",
        )
    if auth_type == AuthType.HEADER and field_name.lower() in RESERVED_HEADERS:
        raise _invalid(
            "identity.field_name_reserved",
            "field_name",
            "Cabecera reservada",
            "La plataforma controla esa cabecera; usa la forma de autenticación que corresponda.",
            "Cabecera reservada.",
        )
    return field_name


async def _check_login_operation(
    session: AsyncSession, project_id: UUID, auth_type: AuthType, operation_id: UUID | None
) -> UUID | None:
    if auth_type != AuthType.LOGIN:
        return None
    if operation_id is None or (
        await repository.live_operation(session, project_id, operation_id) is None
    ):
        raise _invalid(
            "identity.login_operation_required",
            "login_operation_id",
            "Falta la operación de login",
            "Elige la operación de login del contrato vigente (las candidatas vienen marcadas).",
            "Operación de login inexistente o retirada.",
        )
    return operation_id


def _seal(cipher: CredentialCipher, identity: Identity, credential: Credential) -> None:
    identity.encrypted_credential = cipher.encrypt(identity.id, credential)
    identity.key_version = cipher.current_version
    identity.credential_suffix = credential.suffix()
    identity.status = IdentityStatus.ACTIVE


async def _project(session: AsyncSession, project_id: UUID) -> Project:
    project = await repository.lock_project(session, project_id)
    if project is None:
        raise NotFoundError()
    return project


async def _name_free(
    session: AsyncSession, project_id: UUID, name: str, exclude: UUID | None = None
) -> None:
    if await repository.name_taken(session, project_id, name, exclude):
        raise ConflictError(
            "identity.name_taken",
            "Nombre en uso",
            "Otra identidad del proyecto ya se llama así.",
        )


async def _row(session: AsyncSession, project_id: UUID, identity_id: UUID) -> IdentityRow:
    rows, _ = await repository.rows(session, project_id, identity_id=identity_id)
    return rows[0]


# ------------------------------------------------------------------ queries


async def list_identities(
    session: AsyncSession, project_id: UUID, page: int, page_size: int
) -> tuple[list[IdentityRow], int]:
    if await projects_repository.get(session, project_id) is None:
        raise NotFoundError()
    return await repository.rows(session, project_id, page=page, page_size=page_size)


def warnings(row: IdentityRow) -> list[str]:
    """Persistent: an authenticated identity without resources (RF-38)."""
    if row.identity.auth_type != AuthType.NONE and row.resource_count == 0:
        return ["identity.no_resources"]
    return []


# ------------------------------------------------------------------ changes


async def create_identity(
    session: AsyncSession,
    cipher: CredentialCipher,
    project_id: UUID,
    *,
    name: str,
    role: str,
    role_label: str | None,
    auth_type: str,
    credential: Any,
    field_name: str | None,
    login_operation_id: UUID | None,
) -> IdentityRow:
    """CU-09. Saved without testing it: the test is its own request (RF-32)."""
    await _project(session, project_id)
    kind = AuthType(auth_type)
    plain = _credential(kind, credential)
    field_name = _check_field_name(kind, field_name)
    login_operation_id = await _check_login_operation(session, project_id, kind, login_operation_id)
    await _name_free(session, project_id, name)
    if await repository.count_live(session, project_id) >= MAX_IDENTITIES:
        raise ConflictError(
            "identity.limit_reached",
            "Límite de identidades",
            f"Un proyecto admite hasta {MAX_IDENTITIES} identidades, contando la anónima.",
        )
    identity = Identity(
        id=new_id(),  # known before encrypting: it is the associated data
        project_id=project_id,
        name=name,
        role=role,
        role_label=role_label,
        auth_type=kind,
        field_name=field_name,
        login_operation_id=login_operation_id,
    )
    _seal(cipher, identity, plain)
    session.add(identity)
    await session.flush()
    # RF-81 (bitácora) is pending: until then, the log keeps the event. Never the credential.
    log.info("identity_created", project_id=str(project_id), identity_id=str(identity.id))
    return await _row(session, project_id, identity.id)


async def update_identity(
    session: AsyncSession,
    cipher: CredentialCipher,
    project_id: UUID,
    identity_id: UUID,
    changes: dict[str, Any],
) -> IdentityRow:
    await _project(session, project_id)
    identity = await repository.get(session, project_id, identity_id, for_update=True)
    if identity is None:
        raise NotFoundError()
    if identity.auth_type == AuthType.NONE:
        raise _anonymous()
    if not changes:
        raise UnprocessableError(
            "validation.failed",
            "Datos inválidos",
            "Envía al menos un campo para modificar.",
            [FieldIssue(None, "validation.required", "Envía al menos un campo.")],
        )
    kind = AuthType(changes.get("auth_type", identity.auth_type))
    kind_changed = kind != identity.auth_type
    if kind_changed and "credential" not in changes:
        raise _invalid(
            "identity.credential_required",
            "credential",
            "Falta la credencial",
            "Al cambiar la forma de autenticación, envía la credencial de la forma nueva.",
            "Obligatoria al cambiar auth_type.",
        )
    plain = _credential(kind, changes["credential"]) if "credential" in changes else None
    field_name = _check_field_name(kind, changes.get("field_name", identity.field_name))
    login_operation_id = await _check_login_operation(
        session, project_id, kind, changes.get("login_operation_id", identity.login_operation_id)
    )
    if "name" in changes:
        await _name_free(session, project_id, changes["name"], exclude=identity.id)
        identity.name = changes["name"]
    if "role" in changes:
        identity.role = changes["role"]
    if "role_label" in changes:
        identity.role_label = changes["role_label"]
    identity.auth_type = kind
    identity.field_name = field_name
    identity.login_operation_id = login_operation_id
    if plain is not None:
        _seal(cipher, identity, plain)
    await session.flush()
    log.info(
        "identity_updated",
        project_id=str(project_id),
        identity_id=str(identity.id),
        fields=sorted(changes),  # names only, never values
    )
    return await _row(session, project_id, identity.id)


async def delete_identity(
    session: AsyncSession, user: CurrentUser, project_id: UUID, identity_id: UUID
) -> None:
    """Soft delete (modelo.md 7.1; ADR-015): the credential is erased in this transaction."""
    await _project(session, project_id)
    identity = await repository.get(session, project_id, identity_id, for_update=True)
    if identity is None:
        raise NotFoundError()
    if identity.auth_type == AuthType.NONE:
        raise _anonymous()
    if await projects_repository.has_active_run(session, project_id):
        raise ConflictError(
            "project.active_run",
            "Hay una ejecución activa",
            "Espera a que termine la ejecución o cancélala antes de eliminar la identidad.",
        )
    await repository.soft_delete(session, identity, user.id)
    log.info("identity_deleted", project_id=str(project_id), identity_id=str(identity_id))


# ------------------------------------------------------------------ test (RF-32)


@dataclass(frozen=True, slots=True)
class TestOutcome:
    result: ProbeResult
    operation: Operation
    tested_at: Any


def _no_test_operation() -> UnprocessableError:
    return _invalid(
        "identity.no_test_operation",
        "operation_id",
        "No hay una operación para probar",
        "Elige una operación GET vigente, protegida y sin parámetros de ruta.",
        "Sin operación de prueba válida.",
    )


async def _test_operation(
    session: AsyncSession, project_id: UUID, operation_id: UUID | None
) -> Operation:
    if operation_id is not None:
        operation = await repository.live_operation(session, project_id, operation_id)
        # A path parameter would go out as the literal `{id}`: the request would prove nothing.
        if operation is None or operation.method != "GET" or "{" in operation.normalized_path:
            raise _no_test_operation()
        return operation
    candidates = await repository.protected_get_operations(session, project_id)
    if not candidates:
        raise _no_test_operation()
    return candidates[0][0]


def _join(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


def _resolve(document: Any, node: Any) -> Any:
    """Follows internal `$ref`s of a stored schema, within the imported document."""
    for _ in range(MAX_REF_HOPS):
        if not (isinstance(node, dict) and isinstance(node.get("$ref"), str)):
            return node
        ref: str = node["$ref"]
        if not ref.startswith("#/") or document is None:
            return None
        node = document
        for raw in ref.removeprefix("#/").split("/"):
            part = raw.replace("~1", "/").replace("~0", "~")
            node = node.get(part) if isinstance(node, dict) else None
    return None


async def login_request(
    session: AsyncSession, project: Project, operation_id: UUID
) -> LoginRequest | None:
    """Where and how an identity logs in (RF-30); `None` if its operation left the contract.
    Shared with the scanner, which logs in the same way during a run."""
    operation = await repository.live_operation(session, project.id, operation_id)
    described = await repository.latest_description(session, project.id, operation_id)
    if operation is None or described is None:
        return None
    version, contract_id = described
    request: dict[str, Any] = version.schemas.get("request") or {}
    media = next(
        (m for m in request if m == "application/json" or m.endswith("+json")),
        next(iter(request), None),
    )
    schema = request.get(media) if media is not None else None
    document = None
    if isinstance(schema, dict) and "$ref" in schema:
        raw = await repository.contract_document(session, contract_id)
        try:
            async with asyncio.timeout(DOCUMENT_TIMEOUT_SECONDS):
                _, document = await asyncio.to_thread(read_document, raw or b"")
        # The document was valid when imported; if it cannot be read now, the usual names are tried.
        except (ContractError, TimeoutError):  # pragma: no cover - defensive
            document = None
    resolved = _resolve(document, schema)
    properties = resolved.get("properties") if isinstance(resolved, dict) else None
    username, password = login_fields(properties if isinstance(properties, dict) else ())
    return LoginRequest(_join(project.base_url, operation.path), username, password)


async def test_identity(
    session: AsyncSession,
    cipher: CredentialCipher,
    prober: IdentityProber,
    project_id: UUID,
    identity_id: UUID,
    operation_id: UUID | None,
) -> TestOutcome:
    """RF-32. Answers whatever the API said; only a broken precondition is an error."""
    project = await projects_repository.get(session, project_id)
    if project is None:
        raise NotFoundError()
    identity = await repository.get(session, project_id, identity_id, for_update=True)
    if identity is None:
        raise NotFoundError()
    if identity.auth_type == AuthType.NONE:
        raise _anonymous()
    if (
        project.verification_status != VerificationStatus.VERIFIED
        or project.verified_host != project.host
    ):
        raise ConflictError(
            "project.not_verified",
            "Proyecto sin verificar",
            "Verifica la propiedad del dominio antes de enviar peticiones a tu API.",
        )
    operation = await _test_operation(session, project_id, operation_id)
    kind = AuthType(identity.auth_type)
    login = None
    if kind == AuthType.LOGIN:
        if identity.login_operation_id is not None:
            login = await login_request(session, project, identity.login_operation_id)
        if login is None:  # its login operation was retired after the identity was saved
            raise _invalid(
                "identity.login_operation_required",
                "login_operation_id",
                "Falta la operación de login",
                "La operación de login ya no está en el contrato vigente; elige otra.",
                "Operación de login retirada.",
            )
    try:
        if identity.encrypted_credential is None:  # the CHECK constraints make it impossible
            raise CredentialUnreadableError()
        credential = cipher.decrypt(identity.id, identity.encrypted_credential)
    except CredentialUnreadableError:
        # A lost or rotated-out key, or a tampered row: an internal fault, never the analyst's.
        log.error("identity_credential_unreadable", identity_id=str(identity.id))
        raise
    result = await prober.probe(
        Probe(
            host=project.host,
            url=_join(project.base_url, operation.path),
            auth_type=kind,
            credential=credential,
            field_name=identity.field_name,
            login=login,
        )
    )
    identity.last_tested_at = func.now()
    identity.last_test_status_code = result.status_code
    if result.succeeded:
        identity.status = IdentityStatus.ACTIVE  # a working credential is no longer expired
    await session.flush()
    await session.refresh(identity, ["last_tested_at"])
    log.info(
        "identity_tested",
        project_id=str(project_id),
        identity_id=str(identity.id),
        operation_id=str(operation.id),
        status_code=result.status_code,
        failure=None if result.failure is None else result.failure.value,
    )
    return TestOutcome(result=result, operation=operation, tested_at=identity.last_tested_at)
