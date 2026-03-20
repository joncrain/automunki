"""add pkginfo extended fields

Revision ID: f7a8b9c0d1e2
Revises: c5d9e4f6a7b8
Create Date: 2026-03-19 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f7a8b9c0d1e2"
down_revision: str | None = "c5d9e4f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("pkg_info", sa.Column("version_script", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("notes", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("restart_action", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("on_demand", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("pkg_info", sa.Column("force_install_after_date", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("apple_item", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("pkg_info", sa.Column("installable_condition", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("package_path", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("package_complete_url", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("minimum_munki_version", sa.Text(), nullable=True))
    op.add_column("pkg_info", sa.Column("uninstaller_item_location", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("pkg_info", "uninstaller_item_location")
    op.drop_column("pkg_info", "minimum_munki_version")
    op.drop_column("pkg_info", "package_complete_url")
    op.drop_column("pkg_info", "package_path")
    op.drop_column("pkg_info", "installable_condition")
    op.drop_column("pkg_info", "apple_item")
    op.drop_column("pkg_info", "force_install_after_date")
    op.drop_column("pkg_info", "on_demand")
    op.drop_column("pkg_info", "restart_action")
    op.drop_column("pkg_info", "notes")
    op.drop_column("pkg_info", "version_script")
