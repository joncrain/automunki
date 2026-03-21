from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _repo_root_env_file() -> str | None:
    """Prefer the monorepo root `.env` (next to `backend/`), not `backend/.env`.

    Layout: <repo>/backend/automunki/core/config.py → load <repo>/.env only.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "backend").is_dir() and (parent / ".env").is_file():
            return str(parent / ".env")
    legacy = here.parents[3] / ".env"
    return str(legacy) if legacy.is_file() else None


_env_file = _repo_root_env_file()
_settings_kwargs: dict = {"extra": "ignore"}
if _env_file:
    _settings_kwargs["env_file"] = _env_file
    _settings_kwargs["env_file_encoding"] = "utf-8"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(**_settings_kwargs)

    app_name: str = "AutoMunki"
    debug: bool = False

    database_url: str = "postgresql+asyncpg://automunki:automunki@localhost:5432/automunki"
    database_echo: bool = False

    secret_key: str = "change-me-in-production"
    jwt_lifetime_seconds: int = 3600

    github_token: str = ""
    github_repo: str = ""

    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    aws_s3_bucket: str = ""
    cloudfront_distribution_id: str = ""

    munki_repo_pkg_base_url: str = ""
    munki_repo_icon_base_url: str = ""

    #: Directory for UI software icons (PNG). Empty = auto-detect ``<repo>/frontend/public/icons``.
    ui_icons_directory: str = ""

    api_public_url: str = ""

    #: Default AutoPkg execution target when the UI does not send ``runner``:
    #: ``github`` = dispatch GitHub Actions; ``local`` = create run only (execute on a Mac).
    autopkg_runner_mode: Literal["github", "local"] = "github"

    @field_validator("autopkg_runner_mode", mode="before")
    @classmethod
    def _normalize_autopkg_runner_mode(cls, v: object) -> str:
        if v in ("github", "local"):
            return str(v)
        return "github"

    slack_webhook_url: str = ""

    cors_origins: list[str] = ["http://localhost:3000"]


settings = Settings()
