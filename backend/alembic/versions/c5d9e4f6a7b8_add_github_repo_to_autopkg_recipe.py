"""add github_repo to autopkg_recipe

Revision ID: c5d9e4f6a7b8
Revises: b4c8d2e3f5a6
Create Date: 2026-03-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c5d9e4f6a7b8"
down_revision: Union[str, None] = "b4c8d2e3f5a6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("github_repo", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("autopkg_recipe", "github_repo")
