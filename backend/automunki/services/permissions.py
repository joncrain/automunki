"""Resolve effective RBAC permissions for users."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.core.page_keys import ALL_PAGE_KEYS
from automunki.models.rbac import AccessLevel, Role, UserRoleMembership
from automunki.models.user import User


def _rank(level: AccessLevel) -> int:
    return {AccessLevel.none: 0, AccessLevel.read: 1, AccessLevel.write: 2}[level]


def merge_level(a: AccessLevel, b: AccessLevel) -> AccessLevel:
    return a if _rank(a) >= _rank(b) else b


async def _permissions_from_viewer_role(session: AsyncSession) -> dict[str, str]:
    """Seeded Viewer role permissions (read-mostly) when a user has no explicit roles."""
    r = await session.execute(select(Role).where(Role.name == "Viewer").options(selectinload(Role.permissions)))
    role = r.scalar_one_or_none()
    if role is None:
        return {}
    out: dict[str, str] = {}
    for rp in role.permissions:
        if rp.access_level == AccessLevel.read:
            out[rp.page_key] = "read"
        elif rp.access_level == AccessLevel.write:
            out[rp.page_key] = "write"
    return out


async def get_effective_permissions(session: AsyncSession, user: User) -> dict[str, str]:
    """Return ``page_key -> 'read' | 'write'`` (omit 'none'; missing key means no access)."""
    if user.is_superuser:
        return {k: "write" for k in ALL_PAGE_KEYS}

    stmt = (
        select(UserRoleMembership)
        .where(UserRoleMembership.user_id == user.id)
        .options(selectinload(UserRoleMembership.role).selectinload(Role.permissions))
    )
    rows = (await session.execute(stmt)).scalars().all()
    if not rows:
        return await _permissions_from_viewer_role(session)

    acc: dict[str, AccessLevel] = {k: AccessLevel.none for k in ALL_PAGE_KEYS}

    for m in rows:
        role = m.role
        for rp in role.permissions:
            cur = acc.get(rp.page_key, AccessLevel.none)
            acc[rp.page_key] = merge_level(cur, rp.access_level)

    out: dict[str, str] = {}
    for k, v in acc.items():
        if v == AccessLevel.read:
            out[k] = "read"
        elif v == AccessLevel.write:
            out[k] = "write"
    return out


def can_access(permissions: dict[str, str], page_key: str, need_write: bool) -> bool:
    if page_key not in ALL_PAGE_KEYS:
        return True
    level = permissions.get(page_key)
    if level is None:
        return False
    if need_write:
        return level == "write"
    return level in ("read", "write")
