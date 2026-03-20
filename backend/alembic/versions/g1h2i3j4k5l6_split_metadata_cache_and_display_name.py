"""split metadata cache into rows; add imported_display_name on run results

Revision ID: g1h2i3j4k5l6
Revises: f7a8b9c0d1e2, e7f1a3b5c9d2
Create Date: 2026-03-20 12:00:00.000000

"""

import json
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str = "g1h2i3j4k5l6"
down_revision: str | Sequence[str] | None = ("f7a8b9c0d1e2", "e7f1a3b5c9d2")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "autopkg_run_result",
        sa.Column("imported_display_name", sa.Text(), nullable=True),
    )

    op.create_table(
        "autopkg_metadata_cache_entry",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("recipe_key", sa.Text(), nullable=False),
        sa.Column("entry", JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_autopkg_metadata_cache_entry_recipe_key",
        "autopkg_metadata_cache_entry",
        ["recipe_key"],
        unique=True,
    )

    conn = op.get_bind()
    rows = conn.execute(
        text("SELECT cache_data, updated_at FROM autopkg_metadata_cache LIMIT 1")
    ).fetchall()
    for row in rows:
        cache_data, updated_at = row[0], row[1]
        if not isinstance(cache_data, dict):
            continue
        for key, val in cache_data.items():
            if not isinstance(val, dict):
                continue
            conn.execute(
                text(
                    "INSERT INTO autopkg_metadata_cache_entry "
                    "(id, recipe_key, entry, updated_at) "
                    "VALUES (:id, :rk, CAST(:ent AS jsonb), COALESCE(:uat, NOW()))"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "rk": key,
                    "ent": json.dumps(val),
                    "uat": updated_at,
                },
            )

    op.drop_table("autopkg_metadata_cache")


def downgrade() -> None:
    op.create_table(
        "autopkg_metadata_cache",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("cache_data", JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    conn = op.get_bind()
    entry_rows = conn.execute(
        text("SELECT recipe_key, entry, updated_at FROM autopkg_metadata_cache_entry")
    ).fetchall()
    merged: dict = {}
    max_u = None
    for rk, ent, uat in entry_rows:
        if isinstance(ent, dict):
            merged[rk] = ent
        if uat is not None and (max_u is None or uat > max_u):
            max_u = uat
    conn.execute(
        text(
            "INSERT INTO autopkg_metadata_cache (id, cache_data, updated_at) "
            "VALUES (:id, CAST(:cd AS jsonb), COALESCE(:uat, NOW()))"
        ),
        {
            "id": str(uuid.uuid4()),
            "cd": json.dumps(merged),
            "uat": max_u,
        },
    )

    op.drop_index("ix_autopkg_metadata_cache_entry_recipe_key", table_name="autopkg_metadata_cache_entry")
    op.drop_table("autopkg_metadata_cache_entry")
    op.drop_column("autopkg_run_result", "imported_display_name")
