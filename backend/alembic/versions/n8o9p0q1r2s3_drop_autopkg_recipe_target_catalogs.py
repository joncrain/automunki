"""drop autopkg_recipe.target_catalogs (use input_variables.pkginfo.catalogs)

Revision ID: n8o9p0q1r2s3
Revises: m7n8o9p0q1r2
Create Date: 2026-03-20

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "n8o9p0q1r2s3"
down_revision: str | None = "m7n8o9p0q1r2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("autopkg_recipe", "target_catalogs")


def downgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("target_catalogs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
