"""add default_branch to github_recipe_repo

Revision ID: b4c8d2e3f5a6
Revises: a3b7c9d1e2f4
Create Date: 2026-02-27 16:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b4c8d2e3f5a6"
down_revision: str | None = "a3b7c9d1e2f4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "github_recipe_repo",
        sa.Column("default_branch", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("github_recipe_repo", "default_branch")
