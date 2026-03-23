"""Store user profile avatars on disk (not web-public; served with JWT)."""

from __future__ import annotations

import uuid
from pathlib import Path

from automunki.core.config import settings

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_MAX_BYTES = 1024 * 1024


def resolve_user_avatars_directory() -> Path:
    raw = (settings.user_avatars_directory or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "backend").is_dir():
            return (parent / "backend" / "data" / "user-avatars").resolve()
    return (Path.cwd() / "user-avatars").resolve()


def _detect_image(data: bytes) -> tuple[str, str]:
    """Return ``(suffix, media_type)`` for PNG or JPEG."""
    if len(data) > _MAX_BYTES:
        raise ValueError("Image too large (max 1MB)")
    if len(data) < 8:
        raise ValueError("Invalid image file")
    if data.startswith(_PNG_MAGIC):
        return ".png", "image/png"
    if data.startswith(_JPEG_MAGIC):
        return ".jpg", "image/jpeg"
    raise ValueError("Only PNG or JPEG images are supported")


def disk_name_for_user(user_id: uuid.UUID, suffix: str) -> str:
    return f"{user_id}{suffix}"


def remove_stored_avatar(user_id: uuid.UUID, avatar_filename: str | None) -> None:
    """Delete the on-disk file for *avatar_filename* if present."""
    if not avatar_filename:
        return
    root = resolve_user_avatars_directory().resolve()
    path = (root / avatar_filename).resolve()
    if path.parent != root:
        return
    if path.is_file():
        path.unlink()


def write_user_avatar(user_id: uuid.UUID, data: bytes, old_filename: str | None) -> tuple[str, str]:
    """Validate *data*, replace any previous file, return ``(filename, media_type)``."""
    suffix, media_type = _detect_image(data)
    name = disk_name_for_user(user_id, suffix)
    out_dir = resolve_user_avatars_directory()
    out_dir.mkdir(parents=True, exist_ok=True)
    root = out_dir.resolve()

    remove_stored_avatar(user_id, old_filename)

    # Remove other extension for same user (e.g. switched JPEG → PNG)
    for ext in (".png", ".jpg", ".jpeg"):
        alt = root / disk_name_for_user(user_id, ext)
        if alt.is_file() and alt.name != name:
            alt.unlink()

    path = (root / name).resolve()
    if path.parent != root:
        raise ValueError("Invalid path")
    path.write_bytes(data)
    return name, media_type


def media_type_for_filename(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith((".jpg", ".jpeg")):
        return "image/jpeg"
    return "application/octet-stream"


def resolve_avatar_path(filename: str) -> Path | None:
    root = resolve_user_avatars_directory().resolve()
    path = (root / filename).resolve()
    if path.parent != root or not path.is_file():
        return None
    return path
