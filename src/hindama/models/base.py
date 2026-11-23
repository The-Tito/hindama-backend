"""Declarative base and column helpers shared by every model."""

from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import DateTime, MetaData, Text, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from uuid6 import uuid7

# Deterministic constraint names: migrations can refer to them and errors are readable.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

MAX_CONTRACT_BYTES = 5 * 1024 * 1024  # RF-22
MAX_EVIDENCE_BYTES = 64 * 1024  # request + response body truncated to 10 KB (RF-67)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {  # noqa: RUF012 - SQLAlchemy reads it as a class attribute
        datetime: DateTime(timezone=True),
        str: Text(),
        UUID: PgUUID(as_uuid=True),
    }


def new_id() -> UUID:
    """UUID v7: time ordered, so the primary key index stays compact (ADR-013)."""
    return UUID(str(uuid7()))


def uuid_pk() -> Mapped[UUID]:
    return mapped_column(primary_key=True, default=new_id)


def created_at() -> Mapped[datetime]:
    return mapped_column(server_default=func.now())


def one_of(column: str, values: Iterable[StrEnum | str]) -> str:
    """SQL for a CHECK that limits a text column to a catalog."""
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"
