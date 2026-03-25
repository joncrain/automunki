"""HTTP Basic auth for ``/repo``: Argon2 password hashing and verification."""

from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.core.config import settings
from automunki.models.munki_repo_basic_auth import MunkiRepoBasicAuth

_ph = PasswordHasher()
SINGLETON_ID = 1


@dataclass(frozen=True)
class ResolvedRepoBasicAuth:
    """Effective credentials for middleware (env wins over DB when both env vars set)."""

    active: bool
    username: str
    #: Argon2 hash when using DB; empty when using env plaintext path.
    password_hash: str
    #: Plain password only when ``settings.munki_repo_basic_auth_*`` env override is used.
    env_plain_password: str | None
    env_override: bool


def _env_override_active() -> bool:
    u = (settings.munki_repo_basic_auth_user or "").strip()
    p = settings.munki_repo_basic_auth_password or ""
    return bool(u) and len(p) > 0


def env_override_active() -> bool:
    """True when ``MUNKI_REPO_BASIC_AUTH_USER`` and ``MUNKI_REPO_BASIC_AUTH_PASSWORD`` are both set."""
    return _env_override_active()


async def get_singleton_row(session: AsyncSession) -> MunkiRepoBasicAuth | None:
    r = await session.execute(select(MunkiRepoBasicAuth).where(MunkiRepoBasicAuth.id == SINGLETON_ID))
    return r.scalar_one_or_none()


async def resolve_effective_auth(session: AsyncSession) -> ResolvedRepoBasicAuth:
    """Load DB row and apply env override when ``MUNKI_REPO_BASIC_AUTH_*`` are set."""
    if env_override_active():
        u = (settings.munki_repo_basic_auth_user or "").strip()
        p = settings.munki_repo_basic_auth_password or ""
        return ResolvedRepoBasicAuth(
            active=True,
            username=u,
            password_hash="",
            env_plain_password=p,
            env_override=True,
        )

    row = await get_singleton_row(session)
    if row is None:
        return ResolvedRepoBasicAuth(
            active=False,
            username="",
            password_hash="",
            env_plain_password=None,
            env_override=False,
        )

    active = bool(row.enabled and row.username.strip() and row.password_hash.strip())
    return ResolvedRepoBasicAuth(
        active=active,
        username=(row.username or "").strip(),
        password_hash=row.password_hash or "",
        env_plain_password=None,
        env_override=False,
    )


def hash_password(plain: str) -> str:
    return _ph.hash(plain)


def verify_password_against_hash(password_hash: str, plain: str) -> bool:
    if not password_hash or not plain:
        return False
    try:
        _ph.verify(password_hash, plain)
        return True
    except VerifyMismatchError:
        return False


def verify_basic_authorization_header(auth_header: str | None, resolved: ResolvedRepoBasicAuth) -> bool:
    if not resolved.active:
        return True
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    b64 = auth_header[6:].strip()
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if ":" not in decoded:
        return False
    user, _, password = decoded.partition(":")
    u = (user or "").strip()
    un = resolved.username
    if len(u) != len(un):
        return False
    if not secrets.compare_digest(u, un):
        return False
    if resolved.env_plain_password is not None:
        ep = resolved.env_plain_password
        if len(password) != len(ep):
            return False
        return secrets.compare_digest(password, ep)
    return verify_password_against_hash(resolved.password_hash, password)


def build_client_authorization_header_value(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Authorization: Basic {token}"
