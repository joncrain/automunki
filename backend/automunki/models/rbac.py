import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from automunki.models.base import Base, UUIDMixin

if TYPE_CHECKING:
    from automunki.models.user import User


class AccessLevel(enum.StrEnum):
    none = "none"
    read = "read"
    write = "write"


class Role(UUIDMixin, Base):
    __tablename__ = "role"

    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    permissions: Mapped[list["RolePermission"]] = relationship(back_populates="role", cascade="all, delete-orphan")
    memberships: Mapped[list["UserRoleMembership"]] = relationship(back_populates="role", cascade="all, delete-orphan")


class RolePermission(Base):
    __tablename__ = "role_permission"

    role_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("role.id", ondelete="CASCADE"), primary_key=True
    )
    page_key: Mapped[str] = mapped_column(Text, primary_key=True)
    access_level: Mapped[AccessLevel] = mapped_column(
        Enum(AccessLevel, name="access_level_enum", native_enum=True),
        nullable=False,
    )

    role: Mapped["Role"] = relationship(back_populates="permissions")


class UserRoleMembership(Base):
    __tablename__ = "user_role"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("role.id", ondelete="CASCADE"), primary_key=True
    )

    role: Mapped["Role"] = relationship(back_populates="memberships")
    user: Mapped["User"] = relationship("User", back_populates="role_memberships")
