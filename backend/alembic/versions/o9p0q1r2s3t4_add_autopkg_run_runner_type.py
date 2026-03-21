"""add autopkg_run.runner_type (github vs local)

Revision ID: o9p0q1r2s3t4
Revises: n8o9p0q1r2s3
Create Date: 2026-03-20

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "o9p0q1r2s3t4"
down_revision: str | None = "n8o9p0q1r2s3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "autopkg_run",
        sa.Column(
            "runner_type",
            sa.Text(),
            nullable=False,
            server_default="github",
        ),
    )


def downgrade() -> None:
    op.drop_column("autopkg_run", "runner_type")
