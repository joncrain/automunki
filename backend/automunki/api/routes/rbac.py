"""RBAC: roles and user-role assignments (requires ``admin.access`` via middleware)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.api.deps import get_session
from automunki.models.rbac import AccessLevel, Role, RolePermission, UserRoleMembership
from automunki.models.user import User
from automunki.schemas.rbac_api import (
    RoleCreate,
    RolePermissionRow,
    RolePermissionsUpdate,
    RoleRead,
    RoleUpdate,
    UserRolesRead,
    UserRolesUpdate,
)
from automunki.services.user_avatars import remove_stored_avatar

router = APIRouter(prefix="/rbac", tags=["rbac"])


def _role_to_read(r: Role) -> RoleRead:
    perms = [RolePermissionRow(page_key=p.page_key, access_level=p.access_level.value) for p in r.permissions]
    return RoleRead(
        id=r.id,
        name=r.name,
        description=r.description,
        is_system=r.is_system,
        permissions=perms,
    )


@router.get("/roles", response_model=list[RoleRead])
async def list_roles(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Role).options(selectinload(Role.permissions)).order_by(Role.name))
    roles = result.scalars().unique().all()
    return [_role_to_read(r) for r in roles]


@router.post("/roles", response_model=RoleRead)
async def create_role(data: RoleCreate, session: AsyncSession = Depends(get_session)):
    existing = await session.execute(select(Role).where(Role.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Role name already exists")
    role = Role(name=data.name, description=data.description, is_system=False)
    session.add(role)
    await session.commit()
    await session.refresh(role)
    await session.refresh(role, ["permissions"])
    return _role_to_read(role)


@router.patch("/roles/{role_id}", response_model=RoleRead)
async def update_role(
    role_id: uuid.UUID,
    data: RoleUpdate,
    session: AsyncSession = Depends(get_session),
):
    role = await session.get(Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.is_system and data.name is not None and data.name != role.name:
        raise HTTPException(status_code=400, detail="Cannot rename system roles")
    if data.name is not None:
        role.name = data.name
    if data.description is not None:
        role.description = data.description
    await session.commit()
    await session.refresh(role, ["permissions"])
    return _role_to_read(role)


@router.put("/roles/{role_id}/permissions", response_model=RoleRead)
async def replace_role_permissions(
    role_id: uuid.UUID,
    body: RolePermissionsUpdate,
    session: AsyncSession = Depends(get_session),
):
    role = await session.get(Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    await session.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
    for row in body.permissions:
        session.add(
            RolePermission(
                role_id=role_id,
                page_key=row.page_key,
                access_level=AccessLevel(row.access_level),
            )
        )
    await session.commit()
    await session.refresh(role, ["permissions"])
    return _role_to_read(role)


@router.delete("/roles/{role_id}", status_code=204)
async def delete_role(role_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    role = await session.get(Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.is_system:
        raise HTTPException(status_code=400, detail="Cannot delete system roles")
    await session.delete(role)
    await session.commit()


@router.get("/users", response_model=list[UserRolesRead])
async def list_user_roles(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).options(selectinload(User.role_memberships)).order_by(User.email))
    users = result.scalars().unique().all()
    out: list[UserRolesRead] = []
    for u in users:
        rid = [m.role_id for m in u.role_memberships]
        out.append(
            UserRolesRead(
                user_id=u.id,
                email=u.email,
                is_superuser=u.is_superuser,
                role_ids=rid,
            )
        )
    return out


@router.put("/users/{user_id}/roles", response_model=UserRolesRead)
async def set_user_roles(
    user_id: uuid.UUID,
    body: UserRolesUpdate,
    session: AsyncSession = Depends(get_session),
):
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for rid in body.role_ids:
        r = await session.get(Role, rid)
        if not r:
            raise HTTPException(status_code=400, detail=f"Unknown role {rid}")
    await session.execute(delete(UserRoleMembership).where(UserRoleMembership.user_id == user_id))
    for rid in body.role_ids:
        session.add(UserRoleMembership(user_id=user_id, role_id=rid))
    await session.commit()
    await session.refresh(user, ["role_memberships"])
    return UserRolesRead(
        user_id=user.id,
        email=user.email,
        is_superuser=user.is_superuser,
        role_ids=[m.role_id for m in user.role_memberships],
    )


@router.delete("/users/{user_id}", status_code=204)
async def delete_user_account(
    user_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """Remove a user and their RBAC memberships (requires ``admin.access`` write)."""
    actor = getattr(request.state, "user", None)
    if actor is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if actor.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_superuser and not actor.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Only superusers can delete superuser accounts",
        )
    remove_stored_avatar(user.id, user.avatar_filename)
    await session.delete(user)
    await session.commit()
