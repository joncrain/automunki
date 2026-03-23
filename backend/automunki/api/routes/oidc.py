"""OIDC login: redirect to IdP and issue AutoMunki JWT on callback."""

from __future__ import annotations

import secrets
from urllib.parse import urlencode

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.exceptions import UserAlreadyExists
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.api.deps import get_session
from automunki.core.config import settings
from automunki.core.security import UserManager, get_jwt_strategy
from automunki.models.user import User
from automunki.schemas.user import UserCreate

router = APIRouter(prefix="/oidc", tags=["oidc"])


def _oidc_state_token() -> str:
    return pyjwt.encode(
        {"n": secrets.token_hex(16)},
        settings.secret_key,
        algorithm="HS256",
    )


def _verify_oidc_state(token: str) -> None:
    try:
        pyjwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except pyjwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail="Invalid state") from e


@router.get("/authorize")
async def oidc_authorize():
    if settings.auth_mode != "oidc":
        raise HTTPException(status_code=400, detail="OIDC is not enabled")
    if not settings.oidc_authorization_endpoint or not settings.oidc_redirect_url:
        raise HTTPException(status_code=500, detail="OIDC is not configured")
    state = _oidc_state_token()
    q = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": settings.oidc_redirect_url,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": secrets.token_hex(16),
        }
    )
    url = f"{settings.oidc_authorization_endpoint}?{q}"
    return RedirectResponse(url)


@router.get("/callback")
async def oidc_callback(
    code: str | None = Query(None),
    state: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    if settings.auth_mode != "oidc":
        raise HTTPException(status_code=400, detail="OIDC is not enabled")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")
    _verify_oidc_state(state)

    async with httpx.AsyncClient() as client:
        tr = await client.post(
            settings.oidc_token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_url,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
            },
            headers={"Accept": "application/json"},
        )
    if tr.status_code >= 400:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {tr.text}")
    tokens = tr.json()
    access_token = tokens.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="No access_token from IdP")

    async with httpx.AsyncClient() as client:
        ui = await client.get(
            settings.oidc_userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if ui.status_code >= 400:
        raise HTTPException(status_code=400, detail=f"userinfo failed: {ui.text}")
    profile = ui.json()
    sub = profile.get("sub")
    email = profile.get("email")
    if not sub or not email:
        raise HTTPException(status_code=400, detail="OIDC profile missing sub or email")

    issuer = (settings.oidc_issuer or "oidc").strip()

    res = await session.execute(select(User).where(User.oidc_sub == sub, User.oidc_issuer == issuer))
    user = res.scalar_one_or_none()
    if user is None:
        res = await session.execute(select(User).where(User.email == email))
        user = res.scalar_one_or_none()
        if user:
            user.oidc_sub = sub
            user.oidc_issuer = issuer
        else:
            user_db = SQLAlchemyUserDatabase(session, User)
            manager = UserManager(user_db)
            try:
                user = await manager.create(
                    UserCreate(
                        email=email,
                        password=secrets.token_urlsafe(32),
                        is_active=True,
                        is_verified=True,
                    )
                )
            except UserAlreadyExists:
                res = await session.execute(select(User).where(User.email == email))
                user = res.scalar_one()
            user.oidc_sub = sub
            user.oidc_issuer = issuer
    await session.commit()
    await session.refresh(user)

    strategy = get_jwt_strategy()
    jwt_token = await strategy.write_token(user)
    base = settings.public_app_url.rstrip("/")
    return RedirectResponse(url=f"{base}/auth/callback?token={jwt_token}")
