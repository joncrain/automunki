from __future__ import annotations

import enum
from datetime import datetime
from typing import TYPE_CHECKING

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy import DateTime, Enum, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from automunki.models.base import Base

if TYPE_CHECKING:
    from automunki.models.rbac import UserRoleMembership


class UserRole(enum.StrEnum):
    admin = "admin"
    editor = "editor"
    viewer = "viewer"


class User(SQLAlchemyBaseUserTableUUID, Base):
    __tablename__ = "user"

    display_name: Mapped[str | None] = mapped_column(Text)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role_enum", native_enum=True),
        nullable=False,
        default=UserRole.viewer,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    oidc_sub: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: On-disk basename under ``user_avatars_directory`` (e.g. ``{uuid}.png``).
    avatar_filename: Mapped[str | None] = mapped_column(Text, nullable=True)

    role_memberships: Mapped[list[UserRoleMembership]] = relationship(
        "UserRoleMembership", back_populates="user", cascade="all, delete-orphan"
    )
