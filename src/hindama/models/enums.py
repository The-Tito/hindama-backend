"""Catalogs (hindama-docs/03-api/glosario-identificadores.md).

They are stored as `text` + `CHECK` instead of PostgreSQL ENUM types (modelo.md, section 1):
adding a value is a trivial migration. The CHECK constraints are generated from these classes,
so Python and the database cannot disagree.
"""

from enum import StrEnum


class VerificationStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"


class VerificationMethod(StrEnum):
    FILE = "file"
    DNS = "dns"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


class ContractSource(StrEnum):
    FILE = "file"
    URL = "url"


class ContractFormat(StrEnum):
    JSON = "json"
    YAML = "yaml"


class Policy(StrEnum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    OWNER_ONLY = "owner_only"
    OWNER_OR_ADMIN = "owner_or_admin"
    ADMIN_ONLY = "admin_only"


OWNERSHIP_POLICIES = (Policy.OWNER_ONLY, Policy.OWNER_OR_ADMIN)


class IdentityRole(StrEnum):
    ADMIN = "admin"
    USER = "user"
    OTHER = "other"


class AuthType(StrEnum):
    NONE = "none"
    LOGIN = "login"
    BEARER = "bearer"
    COOKIE = "cookie"
    HEADER = "header"


class IdentityStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED_CREDENTIAL = "expired_credential"


class ResourceSource(StrEnum):
    DISCOVERED = "discovered"
    MANUAL = "manual"


class Module(StrEnum):
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    OBJECT_ACCESS = "object_access"
    FUNCTION_ACCESS = "function_access"
    PROPERTY_ACCESS = "property_access"
    RESOURCE_CONSUMPTION = "resource_consumption"
    SQL_INJECTION = "sql_injection"


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


ACTIVE_RUN_STATUSES = (RunStatus.QUEUED, RunStatus.RUNNING)


class EndReason(StrEnum):
    NORMAL = "normal"
    LIMIT_REACHED = "limit_reached"
    CANCELLED_BY_USER = "cancelled_by_user"
    VERIFICATION_INVALID = "verification_invalid"
    HEARTBEAT_EXPIRED = "heartbeat_expired"
    LOST_IN_QUEUE = "lost_in_queue"
    ERROR = "error"


# Which end reasons each final status allows (modelo.md, section 4.2).
END_REASONS_BY_STATUS = {
    RunStatus.COMPLETED: (EndReason.NORMAL, EndReason.LIMIT_REACHED),
    RunStatus.CANCELLED: (EndReason.CANCELLED_BY_USER, EndReason.VERIFICATION_INVALID),
    RunStatus.FAILED: (EndReason.HEARTBEAT_EXPIRED, EndReason.LOST_IN_QUEUE, EndReason.ERROR),
}


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - a verdict, not a password
    FAIL = "fail"
    SKIPPED = "skipped"
    ERROR = "error"


class CreatedResourceStatus(StrEnum):
    PENDING = "pending"
    DELETED = "deleted"
    FAILED = "failed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    NEW = "new"
    PERSISTENT = "persistent"
    RESOLVED = "resolved"
    REGRESSION = "regression"
    ACCEPTED_RISK = "accepted_risk"


OPEN_FINDING_STATUSES = (FindingStatus.NEW, FindingStatus.PERSISTENT, FindingStatus.REGRESSION)


class DismissalReason(StrEnum):
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class ResolutionReason(StrEnum):
    NOT_DETECTED = "not_detected"
    IDENTITY_DELETED = "identity_deleted"
    OPERATION_RETIRED = "operation_retired"


class FindingEventReason(StrEnum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    REGRESSION = "regression"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    REVERTED = "reverted"
    IDENTITY_DELETED = "identity_deleted"
    OPERATION_RETIRED = "operation_retired"


class DailyMetricName(StrEnum):
    NEW_USERS = "new_users"
    DELETED_ACCOUNTS = "deleted_accounts"
    PROJECTS_CREATED = "projects_created"
    RUNS_STARTED = "runs_started"
