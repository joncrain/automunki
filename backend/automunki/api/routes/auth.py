from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.api.deps import get_session
from automunki.api.routes.oidc import router as oidc_router
from automunki.core.config import settings
from automunki.core.page_keys import ALL_PAGE_KEYS
from automunki.core.rbac_middleware import DEV_USER_ID
from automunki.core.security import auth_backend, current_active_user, fastapi_users
from automunki.models.user import User
from automunki.schemas.auth_config import AuthConfigResponse
from automunki.schemas.auth_me import MeResponse
from automunki.schemas.user import UserCreate, UserRead, UserUpdate
from automunki.services.permissions import get_effective_permissions
from automunki.services.user_avatars import (
    media_type_for_filename,
    remove_stored_avatar,
    resolve_avatar_path,
    write_user_avatar,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/config", response_model=AuthConfigResponse)
async def auth_config():
    """Expose ``AUTH_MODE`` so the SPA does not need ``NEXT_PUBLIC_AUTH_MODE``."""
    registration_open = settings.auth_registration_open and settings.auth_mode != "disabled"
    return AuthConfigResponse(
        auth_mode=settings.auth_mode,
        registration_open=registration_open,
    )


@router.get("/me", response_model=MeResponse)
async def read_me(request: Request, session: AsyncSession = Depends(get_session)):
    if settings.auth_mode == "disabled":
        return MeResponse(
            user=UserRead(
                id=DEV_USER_ID,
                email="dev@automunki.local",
                is_active=True,
                is_superuser=True,
                is_verified=True,
                display_name="Dev user",
                role="viewer",
                updated_at=datetime.now(UTC),
                avatar_filename=None,
            ),
            permissions={k: "write" for k in ALL_PAGE_KEYS},
            auth_mode=settings.auth_mode,
        )
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    perms = await get_effective_permissions(session, user)
    return MeResponse(
        user=UserRead.model_validate(user),
        permissions=perms,
        auth_mode=settings.auth_mode,
    )


router.include_router(oidc_router)
router.include_router(fastapi_users.get_auth_router(auth_backend))
router.include_router(fastapi_users.get_register_router(UserRead, UserCreate))

users_router = APIRouter(prefix="/users", tags=["users"])


@users_router.post("/me/avatar", status_code=204)
async def upload_my_avatar(
    file: UploadFile = File(...),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
):
    raw = await file.read()
    u = await session.get(User, user.id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        name, _mt = write_user_avatar(u.id, raw, u.avatar_filename)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    u.avatar_filename = name
    await session.commit()


@users_router.delete("/me/avatar", status_code=204)
async def delete_my_avatar(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
):
    u = await session.get(User, user.id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")
    old = u.avatar_filename
    if old:
        remove_stored_avatar(u.id, old)
    u.avatar_filename = None
    await session.commit()


@users_router.get("/me/avatar")
async def get_my_avatar(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
):
    u = await session.get(User, user.id)
    if u is None or not u.avatar_filename:
        raise HTTPException(status_code=404, detail="No avatar")
    path = resolve_avatar_path(u.avatar_filename)
    if path is None:
        raise HTTPException(status_code=404, detail="No avatar")
    return FileResponse(path, media_type=media_type_for_filename(u.avatar_filename))


users_router.include_router(fastapi_users.get_users_router(UserRead, UserUpdate))
