"""drop github_repo from autopkg_recipe

Revision ID: d6e0f1a2b3c4
Revises: c5d9e4f6a7b8
Create Date: 2026-03-15 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d6e0f1a2b3c4"
down_revision: Union[str, None] = "c5d9e4f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("autopkg_recipe", "github_repo")


def downgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("github_repo", sa.Text(), nullable=True),
    )
