from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_project_root = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_project_root / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AutoMunki"
    debug: bool = False

    database_url: str = (
        "postgresql+asyncpg://automunki:automunki@localhost:5432/automunki"
    )
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

    api_public_url: str = ""

    slack_webhook_url: str = ""

    cors_origins: list[str] = ["http://localhost:3000"]


settings = Settings()
