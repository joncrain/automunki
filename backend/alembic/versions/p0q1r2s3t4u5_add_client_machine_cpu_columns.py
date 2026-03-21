"""Add cpu_arch and CPU counts to client_machine for reporting.

Revision ID: p0q1r2s3t4u5
Revises: o9p0q1r2s3t4
Create Date: 2026-03-20

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "p0q1r2s3t4u5"
down_revision: str | None = "o9p0q1r2s3t4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("client_machine", sa.Column("cpu_arch", sa.Text(), nullable=True))
    op.add_column("client_machine", sa.Column("physical_cpus", sa.Integer(), nullable=True))
    op.add_column("client_machine", sa.Column("logical_cpus", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("client_machine", "logical_cpus")
    op.drop_column("client_machine", "physical_cpus")
    op.drop_column("client_machine", "cpu_arch")
