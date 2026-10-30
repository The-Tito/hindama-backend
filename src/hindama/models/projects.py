"""Project and its configuration (modelo.md, section 3.2).

Isolation (ADR-013): every child table carries `project_id` and `UNIQUE (project_id, id)`, and
references other tables of the same project with composite foreign keys, so a row can never point
to a row of another project. Only `project_id -> projects.id` cascades; the composite keys are
NO ACTION (checked at the end of the statement) so deleting a project works in any order.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from hindama.models.base import MAX_CONTRACT_BYTES, Base, created_at, one_of, uuid_pk
from hindama.models.enums import (
    OWNERSHIP_POLICIES,
    AuthType,
    ContractFormat,
    ContractSource,
    HttpMethod,
    IdentityRole,
    IdentityStatus,
    Policy,
    ResourceSource,
    VerificationMethod,
    VerificationStatus,
)


def project_fk() -> Mapped[UUID]:
    return mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("char_length(name) BETWEEN 1 AND 100", name="name_length"),  # RF-10
        CheckConstraint("char_length(description) <= 500", name="description_length"),
        CheckConstraint("char_length(base_url) <= 2048", name="base_url_length"),
        CheckConstraint(
            one_of("verification_status", VerificationStatus), name="verification_status"
        ),
        CheckConstraint(
            one_of("verification_method", VerificationMethod), name="verification_method"
        ),
        # Verified means verified for the current host (RN-01, RF-13, modelo.md 4.1).
        CheckConstraint(
            "verification_status <> 'verified'"
            " OR (verified_host IS NOT NULL AND verified_host = host"
            " AND verified_at IS NOT NULL AND verification_method IS NOT NULL)",
            name="verified_matches_host",
        ),
        Index(None, "owner_id"),
    )

    id: Mapped[UUID] = uuid_pk()
    owner_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str]
    description: Mapped[str | None]
    base_url: Mapped[str]
    host: Mapped[str]
    verification_code: Mapped[str] = mapped_column(unique=True)
    verification_status: Mapped[str] = mapped_column(
        default=VerificationStatus.PENDING, server_default=VerificationStatus.PENDING
    )
    verification_method: Mapped[str | None]
    verified_at: Mapped[datetime | None]
    verified_host: Mapped[str | None]
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class ContractVersion(Base):
    """One import of the OpenAPI document (RF-26). Immutable."""

    __tablename__ = "contract_versions"
    __table_args__ = (
        UniqueConstraint("project_id", "id"),
        UniqueConstraint("project_id", "number"),
        CheckConstraint("number >= 1", name="number_positive"),
        CheckConstraint(one_of("source", ContractSource), name="source"),
        CheckConstraint(one_of("format", ContractFormat), name="format"),
        CheckConstraint("(source = 'url') = (source_url IS NOT NULL)", name="source_url"),
        CheckConstraint(f"octet_length(document) <= {MAX_CONTRACT_BYTES}", name="document_size"),
        CheckConstraint("operation_count >= 0", name="operation_count"),
    )

    id: Mapped[UUID] = uuid_pk()
    project_id: Mapped[UUID] = project_fk()
    number: Mapped[int]
    source: Mapped[str]
    source_url: Mapped[str | None]
    file_name: Mapped[str | None]
    format: Mapped[str]
    openapi_version: Mapped[str]
    api_title: Mapped[str | None]
    document: Mapped[bytes] = mapped_column(LargeBinary)
    sha256: Mapped[str]
    operation_count: Mapped[int]
    warnings: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    imported_at: Mapped[datetime] = created_at()


class Operation(Base):
    """An operation of the API, stable across contract versions.

    It holds the access policy (RF-39 to RF-43).
    """

    __tablename__ = "operations"
    __table_args__ = (
        UniqueConstraint("project_id", "id"),
        UniqueConstraint("project_id", "method", "normalized_path"),
        CheckConstraint(one_of("method", HttpMethod), name="method"),
        CheckConstraint(one_of("suggested_policy", Policy), name="suggested_policy"),
        CheckConstraint(one_of("policy", Policy), name="policy"),
        # Ownership templates need the owner field (RF-41).
        CheckConstraint(
            f"NOT ({one_of('policy', OWNERSHIP_POLICIES)}) OR owner_field IS NOT NULL",
            name="owner_field_required",
        ),
        # A policy exists only once the analyst confirmed it (RN-08).
        CheckConstraint("(policy IS NULL) = (confirmed_at IS NULL)", name="policy_confirmed"),
    )

    id: Mapped[UUID] = uuid_pk()
    project_id: Mapped[UUID] = project_fk()
    method: Mapped[str]
    normalized_path: Mapped[str]
    path: Mapped[str]  # as it appears in the latest version that includes it
    suggested_policy: Mapped[str | None]
    policy: Mapped[str | None]
    owner_field: Mapped[str | None]
    confirmed_at: Mapped[datetime | None]
    modified_at: Mapped[datetime | None]
    modified_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    resource_parameters: Mapped[list[Any]] = mapped_column(
        JSONB, server_default=text("'[]'::jsonb")
    )
    retired_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at()


class OperationVersion(Base):
    """An operation as it appears in one contract version (RF-24)."""

    __tablename__ = "operation_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["project_id", "contract_version_id"],
            ["contract_versions.project_id", "contract_versions.id"],
        ),
        ForeignKeyConstraint(
            ["project_id", "operation_id"], ["operations.project_id", "operations.id"]
        ),
        Index(None, "project_id", "operation_id"),
    )

    contract_version_id: Mapped[UUID] = mapped_column(primary_key=True)
    operation_id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = project_fk()
    path: Mapped[str]
    openapi_operation_id: Mapped[str | None]  # the contract's own operationId
    summary: Mapped[str | None]
    tags: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    parameters: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    request_body: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    security: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    schemas: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))


class Identity(Base):
    """A test account of the analyst's API (F-05). Soft-deleted: findings reference it."""

    __tablename__ = "identities"
    __table_args__ = (
        UniqueConstraint("project_id", "id"),
        ForeignKeyConstraint(
            ["project_id", "login_operation_id"], ["operations.project_id", "operations.id"]
        ),
        CheckConstraint("char_length(name) BETWEEN 1 AND 100", name="name_length"),
        CheckConstraint(one_of("role", IdentityRole), name="role"),
        CheckConstraint(one_of("auth_type", AuthType), name="auth_type"),
        CheckConstraint(one_of("status", IdentityStatus), name="status"),
        CheckConstraint("char_length(credential_suffix) <= 4", name="suffix_length"),  # RF-31
        # The anonymous identity (RF-34) has no credential and is never deleted.
        CheckConstraint(
            "auth_type <> 'none' OR (encrypted_credential IS NULL AND deleted_at IS NULL)",
            name="anonymous_identity",
        ),
        # Other identities have a credential while they exist; deleting one erases it (ADR-015).
        CheckConstraint(
            "auth_type = 'none' OR (deleted_at IS NULL) = (encrypted_credential IS NOT NULL)",
            name="credential_present",
        ),
        CheckConstraint(
            "(encrypted_credential IS NULL) = (key_version IS NULL)"
            " AND (encrypted_credential IS NULL) = (credential_suffix IS NULL)",
            name="credential_metadata",
        ),
        CheckConstraint(
            "auth_type NOT IN ('cookie', 'header') OR field_name IS NOT NULL",
            name="field_name_required",
        ),
        CheckConstraint(
            "login_operation_id IS NULL OR auth_type = 'login'", name="login_operation_only_login"
        ),
        Index(
            "uq_identities_one_anonymous",
            "project_id",
            unique=True,
            postgresql_where=text("auth_type = 'none'"),
        ),
        Index(
            "uq_identities_active_name",
            "project_id",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    id: Mapped[UUID] = uuid_pk()
    project_id: Mapped[UUID] = project_fk()
    name: Mapped[str]
    role: Mapped[str]
    role_label: Mapped[str | None]
    auth_type: Mapped[str]
    # AES-256-GCM: key_version || nonce || ciphertext || tag, with the identity id as AAD (ADR-007).
    encrypted_credential: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_version: Mapped[int | None]
    credential_suffix: Mapped[str | None]
    field_name: Mapped[str | None]
    login_operation_id: Mapped[UUID | None]
    status: Mapped[str] = mapped_column(
        default=IdentityStatus.ACTIVE, server_default=IdentityStatus.ACTIVE
    )
    last_tested_at: Mapped[datetime | None]
    last_test_status_code: Mapped[int | None]
    deleted_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at()


class Resource(Base):
    """An object of the analyst's API owned by an identity (F-06)."""

    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("project_id", "id"),
        # An object has a single owner.
        UniqueConstraint("project_id", "resource_type", "value"),
        ForeignKeyConstraint(
            ["project_id", "identity_id"], ["identities.project_id", "identities.id"]
        ),
        CheckConstraint(one_of("source", ResourceSource), name="source"),
        Index(None, "project_id", "identity_id"),
    )

    id: Mapped[UUID] = uuid_pk()
    project_id: Mapped[UUID] = project_fk()
    identity_id: Mapped[UUID]
    resource_type: Mapped[str]
    value: Mapped[str]
    source: Mapped[str]
    confirmed: Mapped[bool] = mapped_column(default=False, server_default=text("false"))
    created_at: Mapped[datetime] = created_at()
