"""progress and cancellation columns of runs (contract 0.4.0)

`cells_planned` and `cells_evaluated` give the percentage of the SSE snapshot (RF-51, ADR-006);
`cancel_requested_at` records when the analyst asked to stop a running run (CU-14). The scanner
already has UPDATE on `runs`, so no privilege changes.

Revision ID: 603f278da661
Revises: 5b2e9c4d7a10
Create Date: 2026-11-16 14:33:31.973346

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "603f278da661"
down_revision: str | Sequence[str] | None = "5b2e9c4d7a10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column("cells_planned", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column(
        "runs",
        sa.Column("cells_evaluated", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("runs", sa.Column("cancel_requested_at", sa.DateTime(timezone=True)))
    op.create_check_constraint("cells", "runs", "cells_evaluated BETWEEN 0 AND cells_planned")


def downgrade() -> None:
    op.drop_constraint("cells", "runs", type_="check")
    op.drop_column("runs", "cancel_requested_at")
    op.drop_column("runs", "cells_evaluated")
    op.drop_column("runs", "cells_planned")
