"""The audit log: the sensitive actions and the administrator's search (CU-21, RF-81 to RF-84).

An entry never holds credentials, justifications, analyst free text or a host in clear (RF-83):
`details` only takes identifiers and catalog values, and the host travels as its HMAC.

Most entries are written in the transaction of the action they describe, so an action that rolls
back leaves no entry. A blocked destination is the exception: the request that hit the block
usually fails, and the block must be audited anyway (RF-81), so it goes in its own transaction.
"""

import ipaddress
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hindama.core.audit import BlockCollector, HostHasher, collect_blocks
from hindama.core.destinations import InvalidUrlError, parse_base_url
from hindama.core.errors import FieldIssue, UnprocessableError
from hindama.models import AuditLogEntry
from hindama.models.enums import AuditAction, BlockStage
from hindama.repositories import audit as repository
from hindama.repositories.audit import Filters, NewEntry

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Auditor:
    """Writes the entries of one request, with its user and the browser's IP (RF-82)."""

    session: AsyncSession
    session_factory: async_sessionmaker[AsyncSession]
    hasher: HostHasher
    user_id: UUID
    source_ip: str | None

    async def record_on_project(
        self, action: AuditAction, project_id: UUID, **details: Any
    ) -> None:
        """Like `record`, with the HMAC of the project's current host (RF-83)."""
        host = await repository.project_host(self.session, project_id)
        await self.record(action, project_id=project_id, host=host, **details)

    async def record(
        self,
        action: AuditAction,
        *,
        project_id: UUID | None = None,
        host: str | None = None,
        **details: Any,
    ) -> None:
        """In the request's transaction: committed together with the action, or not at all."""
        await repository.add(self.session, self._entry(action, project_id, host, details))

    @asynccontextmanager
    async def blocks(
        self, stage: BlockStage, project_id: UUID | None = None
    ) -> AsyncIterator[BlockCollector]:
        """Audits every destination the SSRF guard blocked inside the block, even if it raises."""
        with collect_blocks() as collector:
            try:
                yield collector
            finally:
                await write_blocks(
                    self.session_factory,
                    self.hasher,
                    collector,
                    stage,
                    user_id=self.user_id,
                    project_id=project_id,
                    source_ip=self.source_ip,
                )

    async def record_detached(
        self,
        action: AuditAction,
        *,
        project_id: UUID | None = None,
        host: str | None = None,
        **details: Any,
    ) -> None:
        """In its own transaction: survives the failure of the request that caused it."""
        await write_detached(self.session_factory, [self._entry(action, project_id, host, details)])

    def _entry(
        self,
        action: AuditAction,
        project_id: UUID | None,
        host: str | None,
        details: dict[str, Any],
    ) -> NewEntry:
        return NewEntry(
            action=action,
            user_id=self.user_id,
            project_id=project_id,
            host=None if host is None else self.hasher.digest(host),
            source_ip=self.source_ip,
            details=_clean(details),
        )


def _clean(details: dict[str, Any]) -> dict[str, Any]:
    """JSON-ready, without the keys that do not apply (the contract omits them)."""
    return {key: _json(value) for key, value in details.items() if value is not None}


def _json(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, list | tuple):
        return [_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _json(item) for key, item in value.items()}
    return value  # StrEnum values serialize as their text


async def write_detached(
    session_factory: async_sessionmaker[AsyncSession], entries: list[NewEntry]
) -> None:
    """Its own transaction. A failure is logged, never raised: auditing a block must not turn the
    analyst's 422 into a 500, nor end a run."""
    if not entries:
        return
    try:
        async with session_factory() as session, session.begin():
            for entry in entries:
                await repository.add(session, entry)
    except Exception as error:
        # Only the type: the message may include the host of the database.
        log.error(
            "audit_write_failed",
            actions=[entry.action.value for entry in entries],
            error=type(error).__name__,
        )


async def write_blocks(
    session_factory: async_sessionmaker[AsyncSession],
    hasher: HostHasher,
    collector: BlockCollector,
    stage: BlockStage,
    *,
    user_id: UUID | None,
    project_id: UUID | None,
    source_ip: str | None = None,
    run_id: UUID | None = None,
) -> None:
    entries = [
        NewEntry(
            action=AuditAction.DESTINATION_BLOCKED,
            user_id=user_id,
            project_id=project_id,
            host=hasher.digest(block.host),
            source_ip=source_ip,
            details=_clean({"stage": stage, "block_reason": block.reason, "run_id": run_id}),
        )
        for block in collector.distinct()
    ]
    await write_detached(session_factory, entries)


# ----------------------------------------------------------------------------------- the search


def _invalid(field: str, message: str) -> UnprocessableError:
    return UnprocessableError(
        "validation.failed",
        "Datos inválidos",
        "Revisa los filtros de la bitácora.",
        [FieldIssue(field, "validation.format", message)],
    )


def search_host(raw: str) -> str:
    """The host to look for, normalized like a project's (lowercase, IDNA, no port, RF-84).

    Takes a bare name (`api.example.com`), an IP or a whole URL."""
    value = raw.strip()
    if "://" not in value:
        try:  # a bare IPv6 needs brackets inside a URL
            if isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address):
                value = f"[{value}]"
        except ValueError:
            pass
        value = f"https://{value}"
    try:
        return parse_base_url(value).host
    except InvalidUrlError:
        raise _invalid("host", "Escribe un host o una URL válida.") from None


async def list_entries(
    session: AsyncSession,
    hasher: HostHasher,
    *,
    occurred_from: datetime | None,
    occurred_to: datetime | None,
    actions: list[AuditAction],
    user_id: UUID | None,
    host: str | None,
    page: int,
    page_size: int,
) -> tuple[list[AuditLogEntry], int]:
    # Both carry their offset (RFC 3339, checked by the router): they compare as instants.
    if occurred_from is not None and occurred_to is not None and occurred_from > occurred_to:
        raise _invalid("occurred_to", "La fecha final no puede ser anterior a la inicial.")
    filters = Filters(
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        actions=tuple(actions),
        user_id=user_id,
        hosts=None if host is None else tuple(hasher.candidates(search_host(host))),
    )
    return await repository.list_page(session, filters, page, page_size)
