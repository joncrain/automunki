"""Upload software icons (PNG) for the dashboard / Managed Software Center-style paths."""

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from automunki.core.security import current_optional_user
from automunki.models.user import User
from automunki.services.ui_icons import (
    resolve_ui_icons_directory,
    sanitize_icon_basename,
    save_png_icon,
)

router = APIRouter(prefix="/icons", tags=["icons"])


class IconUploadResponse(BaseModel):
    icon_name: str
    filename: str


@router.post("/upload", response_model=IconUploadResponse)
async def upload_icon(
    file: UploadFile = File(...),
    icon_name: str = Form(""),
    _user: User | None = Depends(current_optional_user),
):
    """Save a PNG as ``{icon_name}.png`` under the configured UI icons directory.

    *icon_name* is the Munki pkginfo ``icon_name`` (no ``.png`` suffix). If omitted,
    the upload filename stem is used (if safe).
    """
    raw = await file.read()
    stem = icon_name.strip()
    if not stem and file.filename:
        stem = file.filename.rsplit("/", 1)[-1]
        stem = stem.rsplit(".", 1)[0] if "." in stem else stem
    if not stem:
        raise HTTPException(
            status_code=422,
            detail="icon_name is required (or provide a filename on the upload)",
        )
    try:
        icon_stem, filename = save_png_icon(stem, raw)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    return IconUploadResponse(icon_name=icon_stem, filename=filename)


@router.get("/{basename}")
async def get_icon_file(basename: str):
    """Serve a PNG from the UI icons directory (optional; Next also serves ``/public/icons``)."""
    try:
        safe = sanitize_icon_basename(basename.removesuffix(".png"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    root = resolve_ui_icons_directory().resolve()
    path = (root / f"{safe}.png").resolve()
    if path.parent != root:
        raise HTTPException(status_code=400, detail="Invalid path")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Icon not found")
    return FileResponse(path, media_type="image/png")
