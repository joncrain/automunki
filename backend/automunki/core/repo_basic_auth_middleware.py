"""Require HTTP Basic auth on ``/repo`` when configured (DB or env)."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from automunki.core.db import async_session_factory
from automunki.services.munki_repo_basic_auth import resolve_effective_auth, verify_basic_authorization_header

WWW_AUTHENTICATE = 'Basic realm="Munki Repository"'


class RepoBasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if not path.startswith("/repo"):
            return await call_next(request)
        if request.method == "OPTIONS":
            return await call_next(request)

        async with async_session_factory() as session:
            resolved = await resolve_effective_auth(session)

        if not resolved.active:
            return await call_next(request)

        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            return _unauthorized()

        if verify_basic_authorization_header(auth, resolved):
            return await call_next(request)
        return _unauthorized()


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"detail": "Not authenticated"},
        headers={"WWW-Authenticate": WWW_AUTHENTICATE},
    )
