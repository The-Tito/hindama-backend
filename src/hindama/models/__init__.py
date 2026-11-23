"""SQLAlchemy models: the schema in hindama-docs/02-datos/modelo.md.

All models live in this package, with a single `Base`, to avoid circular imports and so that
Alembic can discover them. Importing this package registers every table.
"""

from hindama.models.accounts import User
from hindama.models.audit import AuditLogEntry, DailyMetric, FindingMetric
from hindama.models.base import Base
from hindama.models.findings import Finding, FindingEvent, FindingOccurrence
from hindama.models.projects import (
    ContractVersion,
    Identity,
    Operation,
    OperationVersion,
    Project,
    Resource,
)
from hindama.models.runs import CreatedResource, Result, Run

__all__ = [
    "AuditLogEntry",
    "Base",
    "ContractVersion",
    "CreatedResource",
    "DailyMetric",
    "Finding",
    "FindingEvent",
    "FindingMetric",
    "FindingOccurrence",
    "Identity",
    "Operation",
    "OperationVersion",
    "Project",
    "Resource",
    "Result",
    "Run",
    "User",
]
