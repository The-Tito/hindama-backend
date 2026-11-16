"""Contract import and the project's operations (CU-08; RF-22 to RF-27; RN-01, RN-02)."""

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.destinations import ALLOWED_SCHEMES
from hindama.core.errors import AppError, FieldIssue, NotFoundError, UnprocessableError
from hindama.core.openapi_import import ContractError, ParsedContract, parse_contract
from hindama.core.safe_http import (
    BlockReason,
    DestinationBlockedError,
    InvalidUrl,
    Limits,
    NetworkError,
    ResponseTooLargeError,
    SafeHttpClient,
)
from hindama.models import ContractVersion, Operation, OperationVersion, Project
from hindama.models.base import MAX_CONTRACT_BYTES
from hindama.models.enums import ContractSource
from hindama.repositories import contracts as repository
from hindama.repositories import projects as projects_repository
from hindama.repositories.contracts import VersionedOperation
from hindama.services.projects import UrlPolicy

log = structlog.get_logger(__name__)

DOWNLOAD_LIMITS = Limits(
    connect_timeout=5.0, read_timeout=15.0, max_redirects=3, max_response_bytes=MAX_CONTRACT_BYTES
)
DOWNLOAD_TIMEOUT_SECONDS = 20.0  # the contract: up to 20 s of download
PARSE_TIMEOUT_SECONDS = 10.0  # and up to 10 s of analysis
MAX_FILE_NAME = 255

UNCHANGED = {
    "code": "contract.unchanged",
    "message": "El documento es idéntico a la versión vigente; no se creó otra.",
    "location": None,
}


class ContractTooLargeError(AppError):
    def __init__(self) -> None:
        super().__init__(
            code="contract.too_large",
            title="El contrato es demasiado grande",
            detail="El contrato no puede pesar más de 5 MB.",
            status=413,
        )


def source_required() -> UnprocessableError:
    return UnprocessableError(
        "contract.source_required",
        "Falta el contrato",
        "Envía el archivo del contrato o su URL, pero no ambos.",
    )


_URL_ERRORS = {
    "contract.url_not_allowed": (
        "La URL del contrato no está permitida",
        "La URL apunta a una dirección privada, local o reservada, o no usa http ni https.",
    ),
    "contract.url_unreachable": (
        "No pudimos descargar el contrato",
        "La URL del contrato no respondió o no devolvió 200. Revisa que sea pública.",
    ),
}


def _url_error(code: str) -> UnprocessableError:
    title, detail = _URL_ERRORS[code]
    return UnprocessableError(code, title, detail, [FieldIssue("url", code, title + ".")])


# ---------------------------------------------------------------- views


@dataclass(frozen=True, slots=True)
class OperationRef:
    id: UUID
    method: str
    path: str


@dataclass(frozen=True, slots=True)
class Changes:
    previous_version: int
    added: list[OperationRef]
    modified: list[OperationRef]
    removed: list[OperationRef]


@dataclass(slots=True)
class ContractView:
    version: ContractVersion
    is_current: bool
    changes: Changes | None
    warnings: list[dict[str, str | None]] = field(default_factory=list)


def _refs(operations: list[VersionedOperation]) -> list[OperationRef]:
    ordered = sorted(operations, key=lambda op: (op.path, op.method))
    return [OperationRef(op.operation_id, op.method, op.path) for op in ordered]


async def changes(session: AsyncSession, version: ContractVersion) -> Changes | None:
    """RF-26: what changed from the previous version; `None` for the first one."""
    previous = await repository.version_by_number(session, version.project_id, version.number - 1)
    if previous is None:
        return None
    before = await repository.operations_of_version(session, previous.id)
    after = await repository.operations_of_version(session, version.id)
    return Changes(
        previous_version=previous.number,
        added=_refs([op for key, op in after.items() if key not in before]),
        modified=_refs(
            [op for key, op in after.items() if key in before and before[key].detail != op.detail]
        ),
        removed=_refs([op for key, op in before.items() if key not in after]),
    )


async def _view(
    session: AsyncSession, version: ContractVersion, momentary: list[dict[str, str | None]]
) -> ContractView:
    latest = await repository.latest(session, version.project_id)
    return ContractView(
        version=version,
        is_current=latest is not None and latest.id == version.id,
        changes=await changes(session, version),
        warnings=[*version.warnings, *momentary],
    )


async def _project(session: AsyncSession, project_id: UUID) -> Project:
    project = await projects_repository.get(session, project_id)
    if project is None:
        raise NotFoundError()  # missing or another analyst's (RN-02)
    return project


async def get_contract(session: AsyncSession, project_id: UUID, contract_id: UUID) -> ContractView:
    await _project(session, project_id)
    version = await repository.get_version(session, project_id, contract_id)
    if version is None:
        raise NotFoundError()
    return await _view(session, version, [])


async def list_contracts(
    session: AsyncSession, project_id: UUID, page: int, page_size: int
) -> tuple[list[ContractVersion], int]:
    await _project(session, project_id)
    return await repository.list_versions(session, project_id, page, page_size)


async def list_operations(
    session: AsyncSession,
    project_id: UUID,
    *,
    include_retired: bool,
    method: str | None,
    page: int,
    page_size: int,
) -> tuple[list[tuple[Operation, OperationVersion]], int]:
    await _project(session, project_id)
    return await repository.list_operations(
        session,
        project_id,
        include_retired=include_retired,
        method=method,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------- import


@dataclass(frozen=True, slots=True)
class Upload:
    content: bytes
    file_name: str | None


async def download(url: str, policy: UrlPolicy) -> bytes:
    """One GET through the SSRF guard, bound to the URL's own host: the contract may live on
    another host than the API, and needs no ownership verification (RN-01 exception)."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise _url_error("contract.url_not_allowed") from None
    if parts.scheme not in ALLOWED_SCHEMES or not host or parts.username or parts.password:
        raise _url_error("contract.url_not_allowed")
    client = SafeHttpClient(
        host,
        resolver=policy.resolver,
        own_addresses=policy.own_addresses,
        limits=DOWNLOAD_LIMITS,
        address_policy=policy.address_policy,
    )
    try:
        async with asyncio.timeout(DOWNLOAD_TIMEOUT_SECONDS), client:
            response = await client.get(url)
    except DestinationBlockedError as error:
        if error.reason == BlockReason.UNRESOLVED:
            raise _url_error("contract.url_unreachable") from None
        raise _url_error("contract.url_not_allowed") from None  # already logged by safe_http
    except ResponseTooLargeError as error:
        if error.status_code == 200:
            raise ContractTooLargeError() from None
        raise _url_error("contract.url_unreachable") from None
    except (NetworkError, InvalidUrl, TimeoutError):
        raise _url_error("contract.url_unreachable") from None
    if response.status_code != 200:
        raise _url_error("contract.url_unreachable")
    return response.content


def _clean_file_name(name: str | None) -> str | None:
    if not name:
        return None
    printable = "".join(c for c in name if c.isprintable()).strip()
    return printable[:MAX_FILE_NAME] or None


async def _parse(raw: bytes, host: str) -> ParsedContract:
    try:
        async with asyncio.timeout(PARSE_TIMEOUT_SECONDS):
            # A thread keeps the event loop free; on timeout it finishes in the background.
            return await asyncio.to_thread(parse_contract, raw, host)
    except ContractError as error:
        title, detail = (
            (
                "Versión no soportada",
                "Hindama admite OpenAPI 3.0 y 3.1. Swagger 2 no está soportado.",
            )
            if error.code == "contract.unsupported_version"
            else (
                "El contrato no es un OpenAPI 3 válido",
                "Corrige los errores indicados y vuelve a importarlo.",
            )
        )
        raise UnprocessableError(
            error.code,
            title,
            detail,
            [FieldIssue(issue.field, issue.code, issue.message) for issue in error.issues],
        ) from None
    except TimeoutError:
        raise UnprocessableError(
            "contract.invalid",
            "El contrato es demasiado complejo",
            "No pudimos analizar el contrato a tiempo. Divide el documento o simplifícalo.",
            [FieldIssue(None, "contract.too_complex", "El análisis superó 10 segundos.")],
        ) from None


async def import_contract(
    session: AsyncSession,
    project_id: UUID,
    *,
    upload: Upload | None,
    url: str | None,
    url_policy: UrlPolicy,
) -> tuple[ContractView, bool]:
    """CU-08. Returns the version and whether it was created (`False`: identical to the current
    one, which comes back with `contract.unchanged`)."""
    if (upload is None) == (url is None):
        raise source_required()
    project = await _project(session, project_id)  # before any download (RN-02)
    if url is not None:
        raw = await download(url, url_policy)
    elif upload is not None:
        if len(upload.content) > MAX_CONTRACT_BYTES:
            raise ContractTooLargeError()
        raw = upload.content
    parsed = await _parse(raw, project.host)
    sha256 = hashlib.sha256(raw).hexdigest()

    # From here on, one import at a time per project: numbers and operations stay consistent.
    await session.scalar(select(Project.id).where(Project.id == project_id).with_for_update())
    current = await repository.latest(session, project_id)
    if current is not None and current.sha256 == sha256:
        return await _view(session, current, [UNCHANGED]), False

    version = ContractVersion(
        project_id=project_id,
        number=1 if current is None else current.number + 1,
        source=ContractSource.FILE if upload is not None else ContractSource.URL,
        source_url=url,
        file_name=_clean_file_name(upload.file_name) if upload is not None else None,
        format=parsed.format,
        openapi_version=parsed.openapi_version,
        api_title=parsed.api_title,
        document=raw,
        sha256=sha256,
        operation_count=len(parsed.operations),
        warnings=[warning.as_json() for warning in parsed.warnings],
    )
    session.add(version)
    await _store_operations(session, project_id, version, parsed)
    await session.refresh(version)
    log.info(
        "contract_imported",
        project_id=str(project_id),
        number=version.number,
        source=version.source,
        operations=version.operation_count,
    )
    return await _view(session, version, []), True


async def _store_operations(
    session: AsyncSession, project_id: UUID, version: ContractVersion, parsed: ParsedContract
) -> None:
    """Operations are stable across versions by (method, normalized path) (ADR-014): new ones are
    added, missing ones retired, and ones that come back are no longer retired."""
    existing = await repository.operations_by_key(session, project_id)
    now = datetime.now(UTC)
    present: set[tuple[str, str]] = set()
    rows: list[tuple[Operation, int]] = []
    for index, parsed_op in enumerate(parsed.operations):
        key = (parsed_op.method, parsed_op.normalized_path)
        present.add(key)
        operation = existing.get(key)
        if operation is None:
            operation = Operation(
                project_id=project_id,
                method=parsed_op.method,
                normalized_path=parsed_op.normalized_path,
                path=parsed_op.path,
            )
            session.add(operation)
        operation.path = parsed_op.path
        operation.retired_at = None
        rows.append((operation, index))
    for key, operation in existing.items():
        if key not in present and operation.retired_at is None:
            operation.retired_at = now
    await session.flush()
    session.add_all(
        OperationVersion(
            contract_version_id=version.id,
            operation_id=operation.id,
            project_id=project_id,
            path=parsed.operations[index].path,
            openapi_operation_id=parsed.operations[index].operation_id,
            summary=parsed.operations[index].summary,
            tags=parsed.operations[index].tags,
            parameters=parsed.operations[index].parameters,
            request_body=parsed.operations[index].request_body,
            security=parsed.operations[index].security,
            schemas=parsed.operations[index].schemas,
        )
        for operation, index in rows
    )
    await session.flush()
