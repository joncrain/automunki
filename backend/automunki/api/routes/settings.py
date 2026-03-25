from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.api.deps import get_session
from automunki.core.config import settings
from automunki.models.munki_repo_basic_auth import MunkiRepoBasicAuth
from automunki.services.munki_repo_basic_auth import (
    SINGLETON_ID,
    build_client_authorization_header_value,
    env_override_active,
    get_singleton_row,
    hash_password,
)

router = APIRouter(prefix="/settings", tags=["settings"])


class UiSettingsRead(BaseModel):
    github_repo: str
    autopkg_runner_mode: str


@router.get("/ui", response_model=UiSettingsRead)
async def get_ui_settings() -> UiSettingsRead:
    """Read-only UI config. Same access model as other read routes (no JWT required)."""
    return UiSettingsRead(
        github_repo=(settings.github_repo or "").strip(),
        autopkg_runner_mode=settings.autopkg_runner_mode,
    )


class MunkiRepoBasicAuthRead(BaseModel):
    enabled: bool
    username: str
    env_override_active: bool


class MunkiRepoBasicAuthUpdate(BaseModel):
    enabled: bool
    username: str = ""
    password: str | None = Field(None, description="New password; omit to keep existing hash")


class MunkiRepoBasicAuthPatchResponse(BaseModel):
    enabled: bool
    username: str
    env_override_active: bool
    client_authorization_header: str | None = None


@router.get("/munki-repo-basic-auth", response_model=MunkiRepoBasicAuthRead)
async def get_munki_repo_basic_auth(session: AsyncSession = Depends(get_session)) -> MunkiRepoBasicAuthRead:
    if env_override_active():
        u = (settings.munki_repo_basic_auth_user or "").strip()
        return MunkiRepoBasicAuthRead(enabled=True, username=u, env_override_active=True)

    row = await get_singleton_row(session)
    if row is None:
        return MunkiRepoBasicAuthRead(enabled=False, username="", env_override_active=False)

    return MunkiRepoBasicAuthRead(
        enabled=bool(row.enabled),
        username=(row.username or "").strip(),
        env_override_active=False,
    )


@router.patch("/munki-repo-basic-auth", response_model=MunkiRepoBasicAuthPatchResponse)
async def patch_munki_repo_basic_auth(
    body: MunkiRepoBasicAuthUpdate,
    session: AsyncSession = Depends(get_session),
) -> MunkiRepoBasicAuthPatchResponse:
    if env_override_active():
        raise HTTPException(
            status_code=409,
            detail="Munki repo basic auth is configured via MUNKI_REPO_BASIC_AUTH_USER / "
            "MUNKI_REPO_BASIC_AUTH_PASSWORD; clear those to manage credentials in the database.",
        )

    row = await get_singleton_row(session)
    if row is None:
        row = MunkiRepoBasicAuth(id=SINGLETON_ID, enabled=False, username="", password_hash="")
        session.add(row)
        await session.flush()

    username = (body.username or "").strip()

    if body.password is not None:
        if body.password == "":
            row.password_hash = ""
        else:
            row.password_hash = hash_password(body.password)

    if body.enabled:
        if not username:
            raise HTTPException(status_code=400, detail="username is required when enabled is true")
        if not (row.password_hash or "").strip():
            raise HTTPException(
                status_code=400,
                detail="password is required when enabling (no stored password yet)",
            )
        row.enabled = True
        row.username = username
    else:
        row.enabled = False
        row.username = username

    await session.commit()
    await session.refresh(row)

    client_header: str | None = None
    if body.password and body.password != "" and body.enabled and username:
        client_header = build_client_authorization_header_value(username, body.password)

    return MunkiRepoBasicAuthPatchResponse(
        enabled=bool(row.enabled),
        username=(row.username or "").strip(),
        env_override_active=False,
        client_authorization_header=client_header,
    )
