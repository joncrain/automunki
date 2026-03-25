"""Singleton row for optional HTTP Basic auth on ``/repo``."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from automunki.models.base import Base


class MunkiRepoBasicAuth(Base):
    """Single row (``id`` = 1) storing hashed credentials for munki clients."""

    __tablename__ = "munki_repo_basic_auth"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(default=False)
    username: Mapped[str] = mapped_column(Text, default="")
    password_hash: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
