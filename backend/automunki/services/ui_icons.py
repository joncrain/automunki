"""Write UI / Munki-style PNG icons to disk (Next.js ``public/icons`` by default)."""

import re
from pathlib import Path

from automunki.core.config import settings

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_MAX_BYTES = 2 * 1024 * 1024


def resolve_ui_icons_directory() -> Path:
    raw = (settings.ui_icons_directory or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        pub = parent / "frontend" / "public"
        if pub.is_dir():
            return (pub / "icons").resolve()
    return (Path.cwd() / "icons").resolve()


def sanitize_icon_basename(name: str) -> str:
    """Munki ``icon_name``: filename stem, safe for disk and URLs."""
    s = name.strip()
    s = re.sub(r"\.png$", "", s, flags=re.IGNORECASE)
    s = re.sub(r"[^\w.\-]+", "_", s, flags=re.UNICODE)
    s = s.strip("._-")
    if not s or len(s) > 120:
        raise ValueError("Invalid icon name")
    if ".." in s or "/" in s or "\\" in s:
        raise ValueError("Invalid icon name")
    return s


def validate_png(data: bytes) -> None:
    if len(data) > _MAX_BYTES:
        raise ValueError("File too large (max 2MB)")
    if len(data) < 8 or not data.startswith(_PNG_MAGIC):
        raise ValueError("Only PNG images are supported")


def save_png_icon(stem: str, data: bytes) -> tuple[str, str]:
    """Write ``{stem}.png`` and return ``(icon_name, filename)``."""
    validate_png(data)
    safe = sanitize_icon_basename(stem)
    out_dir = resolve_ui_icons_directory()
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{safe}.png"
    path = out_dir / filename
    path.write_bytes(data)
    return safe, filename
