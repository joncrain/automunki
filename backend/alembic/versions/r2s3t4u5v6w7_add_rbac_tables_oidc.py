"""Add RBAC tables, OIDC columns on user, seed roles.

Revision ID: r2s3t4u5v6w7
Revises: q1r2s3t4u5v6
Create Date: 2026-03-23

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "r2s3t4u5v6w7"
down_revision: str | None = "q1r2s3t4u5v6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE_VIEWER = "a1111111-1111-4111-8111-111111111101"
ROLE_EDITOR = "a1111111-1111-4111-8111-111111111102"
ROLE_ADMIN = "a1111111-1111-4111-8111-111111111103"

PAGES = [
    "overview",
    "munki.software",
    "munki.manifests",
    "munki.catalogs",
    "autopkg.runs",
    "autopkg.recipes",
    "autopkg.discover",
    "autopkg.approvals",
    "reporting.devices",
    "reporting.installs",
    "admin.audit",
    "admin.settings",
    "admin.access",
]


def upgrade() -> None:
    op.create_table(
        "role",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_role")),
        sa.UniqueConstraint("name", name=op.f("uq_role_name")),
    )
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE access_level_enum AS ENUM ('none', 'read', 'write');
        EXCEPTION
            WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    access_level = postgresql.ENUM(
        "none", "read", "write", name="access_level_enum", create_type=False
    )
    op.create_table(
        "role_permission",
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("page_key", sa.Text(), nullable=False),
        sa.Column("access_level", access_level, nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["role.id"], name=op.f("fk_role_permission_role_id_role"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("role_id", "page_key", name=op.f("pk_role_permission")),
    )
    op.create_table(
        "user_role",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], name=op.f("fk_user_role_user_id_user"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["role.id"], name=op.f("fk_user_role_role_id_role"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_id", name=op.f("pk_user_role")),
    )

    op.add_column("user", sa.Column("oidc_sub", sa.Text(), nullable=True))
    op.add_column("user", sa.Column("oidc_issuer", sa.Text(), nullable=True))
    op.create_index(
        "ix_user_oidc_issuer_sub",
        "user",
        ["oidc_issuer", "oidc_sub"],
        unique=True,
        postgresql_where=sa.text("oidc_sub IS NOT NULL AND oidc_issuer IS NOT NULL"),
    )

    role_table = sa.table(
        "role",
        sa.column("id", postgresql.UUID()),
        sa.column("name", sa.Text()),
        sa.column("description", sa.Text()),
        sa.column("is_system", sa.Boolean()),
    )
    op.bulk_insert(
        role_table,
        [
            {
                "id": ROLE_VIEWER,
                "name": "Viewer",
                "description": "Read-only access to operational pages",
                "is_system": True,
            },
            {
                "id": ROLE_EDITOR,
                "name": "Editor",
                "description": "Manage Munki, AutoPkg, and reporting content",
                "is_system": True,
            },
            {
                "id": ROLE_ADMIN,
                "name": "Administrator",
                "description": "Full access including admin and access management",
                "is_system": True,
            },
        ],
    )

    def perms_for_viewer() -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        for pk in PAGES:
            lvl = "none" if pk == "admin.access" else "read"
            rows.append((ROLE_VIEWER, pk, lvl))
        return rows

    def perms_for_editor() -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        for pk in PAGES:
            if pk in ("overview", "admin.audit", "admin.settings"):
                lvl = "read"
            elif pk == "admin.access":
                lvl = "none"
            else:
                lvl = "write"
            rows.append((ROLE_EDITOR, pk, lvl))
        return rows

    def perms_for_admin() -> list[tuple[str, str, str]]:
        return [(ROLE_ADMIN, pk, "write") for pk in PAGES]

    ins = text(
        """
        INSERT INTO role_permission (role_id, page_key, access_level)
        VALUES (:rid, :pk, CAST(:al AS access_level_enum))
        ON CONFLICT (role_id, page_key) DO NOTHING
        """
    )
    conn = op.get_bind()
    for rid, pk, al in perms_for_viewer() + perms_for_editor() + perms_for_admin():
        conn.execute(ins, {"rid": rid, "pk": pk, "al": al})

    op.execute(
        sa.text("""
        INSERT INTO user_role (user_id, role_id)
        SELECT u.id, CAST(:rid_admin AS uuid)
        FROM "user" u
        WHERE u.is_superuser = true
        ON CONFLICT (user_id, role_id) DO NOTHING
        """).bindparams(rid_admin=ROLE_ADMIN)
    )
    op.execute(
        sa.text("""
        INSERT INTO user_role (user_id, role_id)
        SELECT u.id, CAST(:rid AS uuid)
        FROM "user" u
        WHERE u.is_superuser = false AND u.role::text = 'admin'
          AND NOT EXISTS (SELECT 1 FROM user_role ur WHERE ur.user_id = u.id)
        """).bindparams(rid=ROLE_ADMIN)
    )
    op.execute(
        sa.text("""
        INSERT INTO user_role (user_id, role_id)
        SELECT u.id, CAST(:rid AS uuid)
        FROM "user" u
        WHERE u.is_superuser = false AND u.role::text = 'editor'
          AND NOT EXISTS (SELECT 1 FROM user_role ur WHERE ur.user_id = u.id)
        """).bindparams(rid=ROLE_EDITOR)
    )
    op.execute(
        sa.text("""
        INSERT INTO user_role (user_id, role_id)
        SELECT u.id, CAST(:rid AS uuid)
        FROM "user" u
        WHERE u.is_superuser = false AND u.role::text = 'viewer'
          AND NOT EXISTS (SELECT 1 FROM user_role ur WHERE ur.user_id = u.id)
        """).bindparams(rid=ROLE_VIEWER)
    )


def downgrade() -> None:
    op.drop_index("ix_user_oidc_issuer_sub", table_name="user")
    op.drop_column("user", "oidc_issuer")
    op.drop_column("user", "oidc_sub")
    op.drop_table("user_role")
    op.drop_table("role_permission")
    op.drop_table("role")
    op.execute("DROP TYPE IF EXISTS access_level_enum")
