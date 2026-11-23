"""`/admin/*`: the administrator's panel, never the content of a project (RN-03, RF-80).

`GET /admin/audit-log` (CU-21; RF-81 to RF-84). The administrator's session is the only one the
`audit_log` policy lets read (RLS on `app.role`); the analyst gets 403 before any query.
"""

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import AfterValidator, BeforeValidator

from hindama.api.dependencies import Admin, DbSession, Hasher
from hindama.api.projects import MAX_PAGE
from hindama.api.runs import unique
from hindama.models import AuditLogEntry as AuditLogRow
from hindama.models.enums import AuditAction
from hindama.schemas.admin import AuditDetails, AuditLogEntry, AuditLogPage
from hindama.schemas.common import SINGLE_LINE
from hindama.services import audit as service

router = APIRouter(tags=["Admin"])

# RFC 3339 `date-time`, as the contract's `format`: with time and offset. Pydantic alone would also
# take a Unix timestamp (`0.5`) or a date without time (found by Schemathesis, ST201).
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})", re.ASCII
)


def _rfc3339(value: object) -> object:
    if isinstance(value, str) and not _RFC3339.fullmatch(value):
        raise ValueError("not an RFC 3339 date-time")
    return value


DateTime = Annotated[datetime, BeforeValidator(_rfc3339)]


def _entry(row: AuditLogRow) -> AuditLogEntry:
    return AuditLogEntry(
        id=row.id,
        occurred_at=row.occurred_at,
        action=AuditAction(row.action),
        user_id=row.user_id,
        project_id=row.project_id,
        source_ip=None if row.source_ip is None else str(row.source_ip),
        details=AuditDetails.stored(row.details),
    )


@router.get(
    "/admin/audit-log",
    operation_id="listAuditLog",
    summary="Bitácora de acciones sensibles",
)
async def list_audit_log(
    _: Admin,
    db: DbSession,
    hasher: Hasher,
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    occurred_from: DateTime | None = None,
    occurred_to: DateTime | None = None,
    actions: Annotated[
        list[AuditAction],
        AfterValidator(unique),
        Query(alias="action", json_schema_extra={"uniqueItems": True}),
    ] = [],  # noqa: B006 - FastAPI copies the default; a query list is never shared
    user_id: UUID | None = None,
    host: Annotated[str | None, Query(min_length=1, max_length=2048, pattern=SINGLE_LINE)] = None,
) -> AuditLogPage:
    rows, total = await service.list_entries(
        db,
        hasher,
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        actions=actions,
        user_id=user_id,
        host=host,
        page=page,
        page_size=page_size,
    )
    return AuditLogPage(
        items=[_entry(row) for row in rows], total=total, page=page, page_size=page_size
    )
