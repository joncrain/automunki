"""drop autopkg_repo; add autopkg_recipe.source_repo_full_name

Revision ID: j4k5l6m7n8o9
Revises: i3j4k5l6m7n8
Create Date: 2026-03-20 20:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "j4k5l6m7n8o9"
down_revision: str | None = "i3j4k5l6m7n8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "autopkg_recipe",
        sa.Column("source_repo_full_name", sa.Text(), nullable=True),
    )
    op.execute(
        sa.text(
            """
            UPDATE autopkg_recipe AS r
            SET source_repo_full_name = a.name
            FROM autopkg_repo AS a
            WHERE r.repo_id = a.id
            """
        )
    )
    op.create_index(
        op.f("ix_autopkg_recipe_source_repo_full_name"),
        "autopkg_recipe",
        ["source_repo_full_name"],
        unique=False,
    )
    op.drop_index(op.f("ix_autopkg_recipe_repo_id"), table_name="autopkg_recipe")
    op.drop_constraint(
        op.f("fk_autopkg_recipe_repo_id_autopkg_repo"),
        "autopkg_recipe",
        type_="foreignkey",
    )
    op.drop_column("autopkg_recipe", "repo_id")
    op.drop_table("autopkg_repo")


def downgrade() -> None:
    op.drop_index(
        op.f("ix_autopkg_recipe_source_repo_full_name"),
        table_name="autopkg_recipe",
    )
    op.create_table(
        "autopkg_repo",
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_autopkg_repo")),
        sa.UniqueConstraint("url", name=op.f("uq_autopkg_repo_url")),
    )
    op.add_column(
        "autopkg_recipe",
        sa.Column("repo_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_autopkg_recipe_repo_id_autopkg_repo"),
        "autopkg_recipe",
        "autopkg_repo",
        ["repo_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        op.f("ix_autopkg_recipe_repo_id"),
        "autopkg_recipe",
        ["repo_id"],
        unique=False,
    )
    op.drop_column("autopkg_recipe", "source_repo_full_name")
