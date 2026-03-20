"""rename core Munki tables to munki_* prefix, autopkg trust table, drop icon

Revision ID: i3j4k5l6m7n8
Revises: h2i3j4k5l6m7
Create Date: 2026-03-20 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "i3j4k5l6m7n8"
down_revision: str | None = "h2i3j4k5l6m7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("icon")

    op.rename_table("trust_change_request", "autopkg_trust_change_request")
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS ix_trust_change_request_recipe_id "
            "RENAME TO ix_autopkg_trust_change_request_recipe_id"
        )
    )

    op.rename_table("promotion_rule", "munki_promotion_rule")
    op.rename_table("pkg_info_catalog", "munki_pkginfo_catalog")
    op.rename_table("manifest_item", "munki_manifest_item")
    op.rename_table("manifest_inclusion", "munki_manifest_inclusion")
    op.rename_table("manifest_catalog", "munki_manifest_catalog")
    op.rename_table("manifest", "munki_manifest")
    op.rename_table("pkg_info", "munki_pkginfo")
    op.rename_table("catalog", "munki_catalog")

    op.execute(
        sa.text(
            "ALTER TABLE munki_pkginfo RENAME CONSTRAINT uq_pkg_info_name_version "
            "TO uq_munki_pkginfo_name_version"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "ALTER TABLE munki_pkginfo RENAME CONSTRAINT uq_munki_pkginfo_name_version "
            "TO uq_pkg_info_name_version"
        )
    )

    op.rename_table("munki_catalog", "catalog")
    op.rename_table("munki_pkginfo", "pkg_info")
    op.rename_table("munki_manifest", "manifest")
    op.rename_table("munki_manifest_catalog", "manifest_catalog")
    op.rename_table("munki_manifest_inclusion", "manifest_inclusion")
    op.rename_table("munki_manifest_item", "manifest_item")
    op.rename_table("munki_pkginfo_catalog", "pkg_info_catalog")
    op.rename_table("munki_promotion_rule", "promotion_rule")

    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS ix_autopkg_trust_change_request_recipe_id "
            "RENAME TO ix_trust_change_request_recipe_id"
        )
    )
    op.rename_table("autopkg_trust_change_request", "trust_change_request")

    op.create_table(
        "icon",
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("s3_path", sa.Text(), nullable=True),
        sa.Column("content_type", sa.Text(), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_icon")),
        sa.UniqueConstraint("name", name=op.f("uq_icon_name")),
    )
