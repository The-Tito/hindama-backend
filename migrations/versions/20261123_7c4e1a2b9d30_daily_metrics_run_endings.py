"""count cancelled and failed runs in daily_metrics

The administrator's statistics (CU-20, RF-78) show the runs of a period with how many were
cancelled and how many failed. `runs_started` existed but nothing wrote it; this migration adds
`runs_cancelled` and `runs_failed` to the catalog. Like every catalog, it is text + CHECK generated
from the Python enum (modelo.md, section 1), frozen below.

Revision ID: 7c4e1a2b9d30
Revises: 30d24d99dab2
Create Date: 2026-11-23 12:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7c4e1a2b9d30"
down_revision: str | Sequence[str] | None = "30d24d99dab2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen here: a later change to the enum gets its own migration.
BEFORE = ("new_users", "deleted_accounts", "projects_created", "runs_started")
AFTER = (*BEFORE, "runs_cancelled", "runs_failed")


def _replace(metrics: tuple[str, ...]) -> None:
    quoted = ", ".join(f"'{metric}'" for metric in metrics)
    op.drop_constraint("metric", "daily_metrics", type_="check")
    op.create_check_constraint("metric", "daily_metrics", f"metric IN ({quoted})")


def upgrade() -> None:
    _replace(AFTER)


def downgrade() -> None:
    op.execute("DELETE FROM daily_metrics WHERE metric IN ('runs_cancelled', 'runs_failed')")
    _replace(BEFORE)
