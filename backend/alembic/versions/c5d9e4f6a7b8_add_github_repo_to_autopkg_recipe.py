"""add github_repo to autopkg_recipe

Revision ID: c5d9e4f6a7b8
Revises: b4c8d2e3f5a6
Create Date: 2026-03-14 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c5d9e4f6a7b8"
down_revision: str | None = "b4c8d2e3f5a6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("github_repo", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("autopkg_recipe", "github_repo")
