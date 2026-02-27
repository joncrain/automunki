import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from automunki.models.base import Base, UUIDMixin


class RunStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class RunTriggerType(str, enum.Enum):
    scheduled = "scheduled"
    manual_ui = "manual_ui"
    manual_api = "manual_api"
    workflow_dispatch = "workflow_dispatch"


class RecipeResultStatus(str, enum.Enum):
    success = "success"
    imported = "imported"
    no_change = "no_change"
    failed = "failed"
    trust_failed = "trust_failed"


class ApprovalStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    auto_approved = "auto_approved"


class AutoPkgRepo(UUIDMixin, Base):
    __tablename__ = "autopkg_repo"

    url: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    recipes: Mapped[list["AutoPkgRecipe"]] = relationship(
        back_populates="repo", lazy="selectin"
    )


class GitHubRecipeRepo(UUIDMixin, Base):
    """Locally cached GitHub autopkg recipe repository metadata."""

    __tablename__ = "github_recipe_repo"

    full_name: Mapped[str] = mapped_column(
        Text, unique=True, nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    html_url: Mapped[str] = mapped_column(Text, nullable=False)
    clone_url: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    stars: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    cached_recipes: Mapped[list["GitHubRecipe"]] = relationship(
        back_populates="repo", cascade="all, delete-orphan", lazy="selectin"
    )


class GitHubRecipe(UUIDMixin, Base):
    """Locally cached recipe file from a GitHub autopkg repo."""

    __tablename__ = "github_recipe"

    repo_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("github_recipe_repo.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    filename: Mapped[str] = mapped_column(Text, nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    identifier_guess: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)

    repo: Mapped["GitHubRecipeRepo"] = relationship(back_populates="cached_recipes")


class AutoPkgRecipe(UUIDMixin, Base):
    __tablename__ = "autopkg_recipe"

    identifier: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    parent_recipe: Mapped[str | None] = mapped_column(Text)
    repo_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("autopkg_repo.id", ondelete="SET NULL"),
        index=True,
    )

    override_data: Mapped[dict | None] = mapped_column(JSONB)
    trust_info: Mapped[dict | None] = mapped_column(JSONB)
    input_variables: Mapped[dict | None] = mapped_column(JSONB)

    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_override: Mapped[bool] = mapped_column(Boolean, default=False)

    auto_promote: Mapped[bool] = mapped_column(Boolean, default=False)
    target_catalogs: Mapped[list | None] = mapped_column(JSONB)

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_status: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    repo: Mapped["AutoPkgRepo | None"] = relationship(back_populates="recipes")


class AutoPkgRun(UUIDMixin, Base):
    __tablename__ = "autopkg_run"

    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus, name="run_status_enum", native_enum=True),
        nullable=False,
        default=RunStatus.pending,
    )
    trigger_type: Mapped[RunTriggerType] = mapped_column(
        Enum(RunTriggerType, name="run_trigger_type_enum", native_enum=True),
        nullable=False,
    )
    triggered_by: Mapped[str | None] = mapped_column(Text)
    github_run_id: Mapped[str | None] = mapped_column(Text)
    github_run_url: Mapped[str | None] = mapped_column(Text)

    recipe_filter: Mapped[list | None] = mapped_column(JSONB)
    total_recipes: Mapped[int | None] = mapped_column(Integer)
    recipes_succeeded: Mapped[int | None] = mapped_column(Integer)
    recipes_failed: Mapped[int | None] = mapped_column(Integer)
    recipes_imported: Mapped[int | None] = mapped_column(Integer)

    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    results: Mapped[list["AutoPkgRunResult"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", lazy="selectin"
    )


class AutoPkgRunResult(UUIDMixin, Base):
    __tablename__ = "autopkg_run_result"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("autopkg_run.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recipe_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    recipe_name: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[RecipeResultStatus] = mapped_column(
        Enum(RecipeResultStatus, name="recipe_result_status_enum", native_enum=True),
        nullable=False,
    )

    imported_version: Mapped[str | None] = mapped_column(Text)
    imported_pkg_path: Mapped[str | None] = mapped_column(Text)
    imported_pkginfo_path: Mapped[str | None] = mapped_column(Text)
    imported_catalogs: Mapped[list | None] = mapped_column(JSONB)

    virustotal_results: Mapped[dict | None] = mapped_column(JSONB)
    trust_info_diff: Mapped[dict | None] = mapped_column(JSONB)

    approval_status: Mapped[ApprovalStatus] = mapped_column(
        Enum(ApprovalStatus, name="approval_status_enum", native_enum=True),
        nullable=False,
        default=ApprovalStatus.auto_approved,
    )
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approval_comment: Mapped[str | None] = mapped_column(Text)

    log_output: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    run: Mapped["AutoPkgRun"] = relationship(back_populates="results")
