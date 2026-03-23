"""Enforce JWT authentication and per-page RBAC on ``/api/v1`` routes."""

from __future__ import annotations

import uuid

from fastapi.responses import JSONResponse
from fastapi_users.db import SQLAlchemyUserDatabase
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from automunki.core.audit_context import audit_user_email_ctx, audit_user_id_ctx
from automunki.core.config import settings
from automunki.core.db import async_session_factory
from automunki.core.page_keys import ALL_PAGE_KEYS, api_path_to_page_key
from automunki.core.security import UserManager, get_jwt_strategy
from automunki.models.user import User
from automunki.services.permissions import can_access, get_effective_permissions

# Synthetic identity for audit when ``auth_mode=disabled``.
DEV_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def _is_public_path(path: str, method: str) -> bool:
    if path in ("/health", "/ready", "/metrics"):
        return True
    if path.startswith("/repo"):
        return True
    if path.startswith("/api/docs") or path in ("/api/openapi.json", "/openapi.json"):
        return True
    if path.startswith("/api/v1/auth/oidc"):
        return True
    if path.startswith("/api/v1/auth/"):
        p = path.rstrip("/")
        if p == "/api/v1/auth/me":
            return False
        return True
    # Fleet agent / AutoPkg runner (no interactive user JWT)
    if path.rstrip("/") == "/api/v1/reports/checkin" and method == "POST":
        return True
    if path.startswith("/api/v1/autopkg/runs/") and ("/results" in path or path.rstrip("/").endswith("/complete")):
        return True
    if path.rstrip("/") == "/api/v1/autopkg/pkginfo/ingest" and method == "POST":
        return True
    return False


def _needs_write(method: str) -> bool:
    return method not in ("GET", "HEAD", "OPTIONS")


class RBACMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if not path.startswith("/api/v1"):
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        if _is_public_path(path, request.method):
            return await call_next(request)

        if (
            request.method == "POST"
            and path.rstrip("/") == "/api/v1/auth/register"
            and not settings.auth_registration_open
        ):
            return JSONResponse(status_code=403, content={"detail": "Registration is closed"})

        if settings.auth_mode == "disabled":
            request.state.user = None
            request.state.rbac_user_id = DEV_USER_ID
            request.state.effective_permissions = {k: "write" for k in ALL_PAGE_KEYS}
            tid = audit_user_id_ctx.set(DEV_USER_ID)
            tem = audit_user_email_ctx.set("dev@automunki.local")
            try:
                return await call_next(request)
            finally:
                audit_user_id_ctx.reset(tid)
                audit_user_email_ctx.reset(tem)

        auth = request.headers.get("Authorization")
        token = None
        if auth and auth.startswith("Bearer "):
            token = auth[7:].strip()

        if not token:
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

        page_key = api_path_to_page_key(path)
        need_write = _needs_write(request.method)

        async with async_session_factory() as session:
            strategy = get_jwt_strategy()
            user_db = SQLAlchemyUserDatabase(session, User)
            user_manager = UserManager(user_db)
            user = await strategy.read_token(token, user_manager)
            if user is None or not user.is_active:
                return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

            perms = await get_effective_permissions(session, user)

        request.state.user = user
        request.state.rbac_user_id = user.id
        request.state.effective_permissions = perms

        tid = audit_user_id_ctx.set(user.id)
        tem = audit_user_email_ctx.set(user.email)
        try:
            if page_key is None:
                return await call_next(request)

            if not can_access(perms, page_key, need_write):
                return JSONResponse(status_code=403, content={"detail": "Forbidden"})

            return await call_next(request)
        finally:
            audit_user_id_ctx.reset(tid)
            audit_user_email_ctx.reset(tem)
