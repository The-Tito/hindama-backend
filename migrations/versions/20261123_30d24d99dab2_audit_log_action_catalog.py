"""limit audit_log.action to the catalog of RF-81

The table existed since the first migration with a free `action`; task 4.3 fixes the catalog
(contract 0.7.0, `AuditAction`). Like every other catalog, it is text + CHECK generated from the
Python enum (modelo.md, section 1), frozen below. The table is empty in every environment so far: no entry was
ever written before this task.

Revision ID: 30d24d99dab2
Revises: 603f278da661
Create Date: 2026-11-23 08:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "30d24d99dab2"
down_revision: str | Sequence[str] | None = "603f278da661"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen here: a later change to the enum gets its own migration.
ACTIONS = (
    "account_created",
    "account_deleted",
    "project_created",
    "project_deleted",
    "project_verified",
    "project_verification_lost",
    "identity_created",
    "identity_deleted",
    "run_launched",
    "run_cancelled",
    "finding_dismissed",
    "finding_dismissal_reverted",
    "destination_blocked",
)


def upgrade() -> None:
    quoted = ", ".join(f"'{action}'" for action in ACTIONS)
    op.create_check_constraint("action", "audit_log", f"action IN ({quoted})")


def downgrade() -> None:
    op.drop_constraint("action", "audit_log", type_="check")
