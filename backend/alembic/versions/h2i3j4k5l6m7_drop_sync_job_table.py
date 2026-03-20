"""drop sync_job (S3/repo sync pipeline removed)

Revision ID: h2i3j4k5l6m7
Revises: g1h2i3j4k5l6
Create Date: 2026-03-20 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "h2i3j4k5l6m7"
down_revision: str | None = "g1h2i3j4k5l6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("sync_job")
    op.execute(sa.text("DROP TYPE IF EXISTS sync_status_enum"))


def downgrade() -> None:
    sync_status = postgresql.ENUM(
        "pending", "running", "completed", "failed", name="sync_status_enum", create_type=False
    )
    sync_status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "sync_job",
        sa.Column("status", sync_status, nullable=False),
        sa.Column("triggered_by", sa.Text(), nullable=True),
        sa.Column("trigger_type", sa.Text(), nullable=True),
        sa.Column("github_run_id", sa.Text(), nullable=True),
        sa.Column("files_synced", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "id",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sync_job")),
    )
