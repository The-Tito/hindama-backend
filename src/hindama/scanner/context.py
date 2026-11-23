"""What a run tests, read once when it starts (architecture 4.3, step «Carga contrato...»).

- The operations of the run's contract version, with the policy the analyst confirmed (RN-08):
  an operation without a confirmed policy is not tested by the policy-based modules.
- The live identities, with their credential decrypted only in memory (RN-11). One that cannot be
  decrypted (a lost key) is left out and logged by id.
- The confirmed resources, by type (RF-35 to RF-37).
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hindama.core.credentials import Credential, CredentialCipher, CredentialUnreadableError
from hindama.core.identity_probe import LoginRequest
from hindama.core.openapi_import import ContractError, read_document
from hindama.models import (
    ContractVersion,
    Identity,
    Operation,
    OperationVersion,
    Project,
    Resource,
    Run,
)
from hindama.models.enums import AuthType, HttpMethod, IdentityRole, IdentityStatus, Policy
from hindama.scanner.schemas import json_schema
from hindama.services.identities import login_request

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Parameter:
    """A path or query parameter declared in the contract."""

    name: str
    location: str  # path, query, header or cookie
    required: bool
    type: str | None  # string, integer... as the import read it


@dataclass(frozen=True, slots=True)
class Target:
    """An operation to test, as described by the run's contract version."""

    id: UUID
    method: HttpMethod
    path: str  # with its `{parameters}`, relative to the project's base URL
    policy: Policy | None  # None: not confirmed, never used to judge (RN-08)
    resource_parameters: tuple[tuple[str, str], ...]  # (parameter, resource type), RF-35
    parameters: tuple[Parameter, ...] = ()
    # The JSON schemas, as stored by the import: they may be a `$ref` into `RunContext.document`.
    request_schema: Any = None
    response_schema: Any = None  # of the first 2xx response with a JSON body


@dataclass(slots=True)
class Actor:
    """An identity of the analyst's API. `credential` is None only for the anonymous one."""

    id: UUID
    name: str
    role: IdentityRole
    auth_type: AuthType
    credential: Credential | None
    field_name: str | None = None
    login: LoginRequest | None = None
    expired: bool = False  # RF-33, set during the run

    @property
    def authenticated(self) -> bool:
        return self.auth_type != AuthType.NONE

    def secrets(self) -> list[str]:
        """Every secret value of the identity, to mask them in evidence (RN-11)."""
        if self.credential is None:
            return []
        values = (self.credential.password, self.credential.token, self.credential.value)
        return [value for value in values if value]


@dataclass(frozen=True, slots=True)
class Owned:
    value: str
    owner_id: UUID


@dataclass(slots=True)
class RunContext:
    run_id: UUID
    project_id: UUID
    base_url: str
    host: str
    targets: list[Target]
    actors: list[Actor]
    resources: dict[str, list[Owned]] = field(default_factory=dict)  # by resource type
    document: Any = None  # the contract version's document, to resolve `$ref`s (schemas.deref)

    def actor(self, identity_id: UUID) -> Actor | None:
        return next((a for a in self.actors if a.id == identity_id), None)


async def load(session: AsyncSession, cipher: CredentialCipher, run: Run) -> RunContext:
    project = await session.get(Project, run.project_id)
    if project is None:  # a run cannot outlive its project (FK, ON DELETE CASCADE)
        raise LookupError("project of the run not found")
    actors = [
        actor
        for identity in await _identities(session, project.id)
        if (actor := await _actor(session, cipher, project, identity)) is not None
    ]
    resources: dict[str, list[Owned]] = defaultdict(list)
    live = {actor.id for actor in actors}
    rows = await session.scalars(
        select(Resource)
        .where(Resource.project_id == project.id, Resource.confirmed.is_(True))
        .order_by(Resource.created_at, Resource.id)
    )
    for resource in rows:
        if resource.identity_id in live:
            resources[resource.resource_type].append(Owned(resource.value, resource.identity_id))
    return RunContext(
        run_id=run.id,
        project_id=project.id,
        base_url=project.base_url.rstrip("/"),
        host=project.host,
        targets=await _targets(session, project.id, run.contract_version_id),
        actors=actors,
        resources=dict(resources),
        document=await _document(session, run.contract_version_id),
    )


async def _document(session: AsyncSession, contract_version_id: UUID | None) -> Any:
    if contract_version_id is None:
        return None
    version = await session.get(ContractVersion, contract_version_id)
    if version is None:
        return None
    try:
        return read_document(version.document)[1]
    except ContractError:  # it was valid when imported: only a schema change could break it
        log.warning("contract_document_unreadable", contract_version_id=str(version.id))
        return None


async def _targets(
    session: AsyncSession, project_id: UUID, contract_version_id: UUID | None
) -> list[Target]:
    if contract_version_id is None:  # only modules that need no contract (Configuration)
        return []
    statement = (
        select(Operation, OperationVersion)
        .join(
            OperationVersion,
            (OperationVersion.project_id == Operation.project_id)
            & (OperationVersion.operation_id == Operation.id),
        )
        .where(
            Operation.project_id == project_id,
            OperationVersion.contract_version_id == contract_version_id,
        )
        .order_by(Operation.normalized_path, Operation.method)
    )
    return [
        Target(
            id=operation.id,
            method=HttpMethod(operation.method),
            path=version.path,
            policy=None if operation.policy is None else Policy(operation.policy),
            resource_parameters=tuple(
                (p["name"], p["resource_type"]) for p in operation.resource_parameters
            ),
            parameters=tuple(
                Parameter(p["name"], p["location"], bool(p.get("required")), p.get("type"))
                for p in version.parameters
                if isinstance(p, dict) and isinstance(p.get("name"), str)
            ),
            request_schema=json_schema(version.schemas.get("request")),
            response_schema=_success_schema(version.schemas.get("responses")),
        )
        for operation, version in await session.execute(statement)
    ]


def _success_schema(responses: Any) -> Any:
    if not isinstance(responses, dict):
        return None
    for status in sorted(responses):
        if status.startswith("2") and (schema := json_schema(responses[status])) is not None:
            return schema
    return None


async def _identities(session: AsyncSession, project_id: UUID) -> list[Identity]:
    rows = await session.scalars(
        select(Identity)
        .where(
            Identity.project_id == project_id,
            Identity.deleted_at.is_(None),
            Identity.status == IdentityStatus.ACTIVE,
        )
        .order_by(Identity.created_at, Identity.id)
    )
    return list(rows)


async def _actor(
    session: AsyncSession, cipher: CredentialCipher, project: Project, identity: Identity
) -> Actor | None:
    auth_type = AuthType(identity.auth_type)
    actor = Actor(
        id=identity.id,
        name=identity.name,
        role=IdentityRole(identity.role),
        auth_type=auth_type,
        credential=None,
        field_name=identity.field_name,
    )
    if auth_type == AuthType.NONE:
        return actor
    try:
        if identity.encrypted_credential is None:  # the CHECK constraints make it impossible
            raise CredentialUnreadableError()
        actor.credential = cipher.decrypt(identity.id, identity.encrypted_credential)
    except CredentialUnreadableError:
        log.error("identity_credential_unreadable", identity_id=str(identity.id))
        return None
    if auth_type == AuthType.LOGIN:
        if identity.login_operation_id is not None:
            actor.login = await login_request(session, project, identity.login_operation_id)
        if actor.login is None:  # its login operation left the contract
            log.warning("identity_without_login", identity_id=str(identity.id))
            return None
    return actor
