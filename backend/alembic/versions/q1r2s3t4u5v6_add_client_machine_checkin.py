"""Add client_machine_checkin for per-device check-in history.

Revision ID: q1r2s3t4u5v6
Revises: p0q1r2s3t4u5
Create Date: 2026-03-20

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "q1r2s3t4u5v6"
down_revision: str | None = "p0q1r2s3t4u5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "client_machine_checkin",
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("machine_id", sa.UUID(), nullable=False),
        sa.Column("checked_in_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["client_machine.id"],
            name=op.f("fk_client_machine_checkin_machine_id_client_machine"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_client_machine_checkin")),
    )
    op.create_index(
        op.f("ix_client_machine_checkin_machine_id"),
        "client_machine_checkin",
        ["machine_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_client_machine_checkin_checked_in_at"),
        "client_machine_checkin",
        ["checked_in_at"],
        unique=False,
    )
    op.create_index(
        "ix_client_machine_checkin_machine_checked",
        "client_machine_checkin",
        ["machine_id", "checked_in_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_client_machine_checkin_machine_checked", table_name="client_machine_checkin")
    op.drop_index(op.f("ix_client_machine_checkin_checked_in_at"), table_name="client_machine_checkin")
    op.drop_index(op.f("ix_client_machine_checkin_machine_id"), table_name="client_machine_checkin")
    op.drop_table("client_machine_checkin")
