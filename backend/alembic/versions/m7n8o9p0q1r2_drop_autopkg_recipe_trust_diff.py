"""drop autopkg_recipe.trust_diff (diff lives on trust_change_request only)

Revision ID: m7n8o9p0q1r2
Revises: k5l6m7n8o9p0
Create Date: 2026-03-20

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "m7n8o9p0q1r2"
down_revision: str | None = "k5l6m7n8o9p0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("autopkg_recipe", "trust_diff")


def downgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("trust_diff", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
