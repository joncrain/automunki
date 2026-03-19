"""add autopkg_metadata_cache table

Revision ID: e7f1a3b5c9d2
Revises: d6e0f1a2b3c4
Create Date: 2026-03-19 20:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str = "e7f1a3b5c9d2"
down_revision: str | None = "d6e0f1a2b3c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "autopkg_metadata_cache",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("cache_data", JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("autopkg_metadata_cache")
