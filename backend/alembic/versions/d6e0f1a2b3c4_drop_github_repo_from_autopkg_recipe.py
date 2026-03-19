"""drop github_repo from autopkg_recipe

Revision ID: d6e0f1a2b3c4
Revises: c5d9e4f6a7b8
Create Date: 2026-03-15 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d6e0f1a2b3c4"
down_revision: str | None = "c5d9e4f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("autopkg_recipe", "github_repo")


def downgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("github_repo", sa.Text(), nullable=True),
    )
