from fastapi import APIRouter
from pydantic import BaseModel

from automunki.core.config import settings

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
