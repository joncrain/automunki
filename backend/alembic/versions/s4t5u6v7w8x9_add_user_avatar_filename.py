"""Add user.avatar_filename for profile images.

Revision ID: s4t5u6v7w8x9
Revises: r2s3t4u5v6w7
Create Date: 2026-03-23

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "s4t5u6v7w8x9"
down_revision: str | None = "r2s3t4u5v6w7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("user", sa.Column("avatar_filename", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("user", "avatar_filename")
