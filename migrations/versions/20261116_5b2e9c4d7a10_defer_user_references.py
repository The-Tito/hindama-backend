"""defer the foreign keys that point to users from inside a project

`finding_events.user_id` and `operations.modified_by` reference `users` without ON DELETE: the row
must not vanish while the user exists. But deleting a user (RF-88) cascades users -> projects ->
finding_events/operations, two levels down, and PostgreSQL checked these NO ACTION keys before
the second level of the cascade had removed the rows: the account could not be deleted once its
analyst had accepted a risk or confirmed a policy.

DEFERRABLE INITIALLY DEFERRED moves the check to COMMIT, when the cascade is complete. The rule is
the same; only its moment changes.

Revision ID: 5b2e9c4d7a10
Revises: 369b4dfef139
Create Date: 2026-11-16 05:30:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "5b2e9c4d7a10"
down_revision: str | Sequence[str] | None = "369b4dfef139"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KEYS = (
    ("finding_events", "fk_finding_events_user_id_users"),
    ("operations", "fk_operations_modified_by_users"),
)


def upgrade() -> None:
    for table, name in KEYS:
        op.execute(f"ALTER TABLE {table} ALTER CONSTRAINT {name} DEFERRABLE INITIALLY DEFERRED")


def downgrade() -> None:
    for table, name in KEYS:
        op.execute(f"ALTER TABLE {table} ALTER CONSTRAINT {name} NOT DEFERRABLE")
