"""add trust status fields and trust_change_request table

Revision ID: a3b7c9d1e2f4
Revises: 5456dfc48cd0
Create Date: 2026-02-27 14:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3b7c9d1e2f4"
down_revision: str | None = "5456dfc48cd0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("trust_status", sa.Text(), server_default="unknown", nullable=False),
    )
    op.add_column(
        "autopkg_recipe",
        sa.Column("trust_diff", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "autopkg_recipe",
        sa.Column("trust_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "autopkg_recipe",
        sa.Column("trust_approved_by", sa.Text(), nullable=True),
    )
    op.add_column(
        "autopkg_recipe",
        sa.Column("trust_approved_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "trust_change_request",
        sa.Column(
            "recipe_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column("old_trust_info", postgresql.JSONB(), nullable=True),
        sa.Column("new_trust_info", postgresql.JSONB(), nullable=True),
        sa.Column("diff", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("reviewed_by", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["recipe_id"],
            ["autopkg_recipe.id"],
            name=op.f("fk_trust_change_request_recipe_id_autopkg_recipe"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_trust_change_request")),
    )
    op.create_index(
        op.f("ix_trust_change_request_recipe_id"),
        "trust_change_request",
        ["recipe_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_trust_change_request_recipe_id"),
        table_name="trust_change_request",
    )
    op.drop_table("trust_change_request")
    op.drop_column("autopkg_recipe", "trust_approved_at")
    op.drop_column("autopkg_recipe", "trust_approved_by")
    op.drop_column("autopkg_recipe", "trust_verified_at")
    op.drop_column("autopkg_recipe", "trust_diff")
    op.drop_column("autopkg_recipe", "trust_status")
