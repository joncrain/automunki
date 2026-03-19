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
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from automunki.models.base import Base, UUIDMixin


class ItemType(enum.StrEnum):
    managed_installs = "managed_installs"
    managed_uninstalls = "managed_uninstalls"
    managed_updates = "managed_updates"
    optional_installs = "optional_installs"
    featured_items = "featured_items"
    default_installs = "default_installs"


class PromotionStrategy(enum.StrEnum):
    manual = "manual"
    auto_time = "auto_time"
    auto_approve = "auto_approve"
    auto_immediate = "auto_immediate"


class SyncStatus(enum.StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class PkgInfo(UUIDMixin, Base):
    __tablename__ = "pkg_info"

    name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(Text, index=True)
    developer: Mapped[str | None] = mapped_column(Text)
    icon_name: Mapped[str | None] = mapped_column(Text)

    installer_item_location: Mapped[str | None] = mapped_column(Text)
    installer_item_hash: Mapped[str | None] = mapped_column(Text)
    installer_item_size: Mapped[int | None] = mapped_column(Integer)
    installed_size: Mapped[int | None] = mapped_column(Integer)
    installer_type: Mapped[str | None] = mapped_column(Text)

    minimum_os_version: Mapped[str | None] = mapped_column(Text)
    maximum_os_version: Mapped[str | None] = mapped_column(Text)

    uninstall_method: Mapped[str | None] = mapped_column(Text)
    unattended_install: Mapped[bool] = mapped_column(Boolean, default=False)
    unattended_uninstall: Mapped[bool] = mapped_column(Boolean, default=False)
    autoremove: Mapped[bool] = mapped_column(Boolean, default=False)
    uninstallable: Mapped[bool] = mapped_column(Boolean, default=True)

    installs: Mapped[dict | None] = mapped_column(JSONB)
    receipts: Mapped[dict | None] = mapped_column(JSONB)
    blocking_applications: Mapped[list | None] = mapped_column(JSONB)
    items_to_copy: Mapped[list | None] = mapped_column(JSONB)
    supported_architectures: Mapped[list | None] = mapped_column(JSONB)
    requires: Mapped[list | None] = mapped_column(JSONB)
    update_for: Mapped[list | None] = mapped_column(JSONB)

    preinstall_script: Mapped[str | None] = mapped_column(Text)
    postinstall_script: Mapped[str | None] = mapped_column(Text)
    preuninstall_script: Mapped[str | None] = mapped_column(Text)
    postuninstall_script: Mapped[str | None] = mapped_column(Text)
    installcheck_script: Mapped[str | None] = mapped_column(Text)
    uninstallcheck_script: Mapped[str | None] = mapped_column(Text)

    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB)
    raw_plist: Mapped[dict | None] = mapped_column(JSONB)

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    catalogs: Mapped[list["Catalog"]] = relationship(
        secondary="pkg_info_catalog", back_populates="pkg_infos", lazy="selectin"
    )

    __table_args__ = (UniqueConstraint("name", "version", name="uq_pkg_info_name_version"),)


class Catalog(UUIDMixin, Base):
    __tablename__ = "catalog"

    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    is_production: Mapped[bool] = mapped_column(Boolean, default=False)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    pkg_infos: Mapped[list["PkgInfo"]] = relationship(
        secondary="pkg_info_catalog", back_populates="catalogs", lazy="selectin"
    )


class PkgInfoCatalog(Base):
    __tablename__ = "pkg_info_catalog"

    pkg_info_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pkg_info.id", ondelete="CASCADE"),
        primary_key=True,
    )
    catalog_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("catalog.id", ondelete="CASCADE"),
        primary_key=True,
    )


class Manifest(UUIDMixin, Base):
    __tablename__ = "manifest"

    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text)
    conditional_items: Mapped[dict | None] = mapped_column(JSONB)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    catalog_refs: Mapped[list["ManifestCatalog"]] = relationship(
        back_populates="manifest", cascade="all, delete-orphan", lazy="selectin"
    )
    items: Mapped[list["ManifestItem"]] = relationship(
        back_populates="manifest", cascade="all, delete-orphan", lazy="selectin"
    )
    included_manifests: Mapped[list["ManifestInclusion"]] = relationship(
        foreign_keys="ManifestInclusion.parent_manifest_id",
        back_populates="parent",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    included_by: Mapped[list["ManifestInclusion"]] = relationship(
        foreign_keys="ManifestInclusion.child_manifest_id",
        back_populates="child",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class ManifestCatalog(Base):
    __tablename__ = "manifest_catalog"

    manifest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("manifest.id", ondelete="CASCADE"),
        primary_key=True,
    )
    catalog_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("catalog.id", ondelete="CASCADE"),
        primary_key=True,
    )
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    manifest: Mapped["Manifest"] = relationship(back_populates="catalog_refs")
    catalog: Mapped["Catalog"] = relationship(lazy="selectin")


class ManifestItem(UUIDMixin, Base):
    __tablename__ = "manifest_item"

    manifest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("manifest.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    item_name: Mapped[str] = mapped_column(Text, nullable=False)
    item_type: Mapped[ItemType] = mapped_column(Enum(ItemType, name="item_type_enum", native_enum=True), nullable=False)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    manifest: Mapped["Manifest"] = relationship(back_populates="items")


class ManifestInclusion(Base):
    __tablename__ = "manifest_inclusion"

    parent_manifest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("manifest.id", ondelete="CASCADE"),
        primary_key=True,
    )
    child_manifest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("manifest.id", ondelete="CASCADE"),
        primary_key=True,
    )
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    parent: Mapped["Manifest"] = relationship(foreign_keys=[parent_manifest_id], back_populates="included_manifests")
    child: Mapped["Manifest"] = relationship(foreign_keys=[child_manifest_id], back_populates="included_by")


class PromotionRule(UUIDMixin, Base):
    __tablename__ = "promotion_rule"

    pkginfo_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source_catalog_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("catalog.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_catalog_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("catalog.id", ondelete="CASCADE"),
        nullable=False,
    )
    strategy: Mapped[PromotionStrategy] = mapped_column(
        Enum(PromotionStrategy, name="promotion_strategy_enum", native_enum=True),
        nullable=False,
        default=PromotionStrategy.manual,
    )
    auto_promote_days: Mapped[int | None] = mapped_column(Integer)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    source_catalog: Mapped["Catalog"] = relationship(foreign_keys=[source_catalog_id])
    target_catalog: Mapped["Catalog"] = relationship(foreign_keys=[target_catalog_id])


class SyncJob(UUIDMixin, Base):
    __tablename__ = "sync_job"

    status: Mapped[SyncStatus] = mapped_column(
        Enum(SyncStatus, name="sync_status_enum", native_enum=True),
        nullable=False,
        default=SyncStatus.pending,
    )
    triggered_by: Mapped[str | None] = mapped_column(Text)
    trigger_type: Mapped[str | None] = mapped_column(Text)
    github_run_id: Mapped[str | None] = mapped_column(Text)
    files_synced: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Icon(UUIDMixin, Base):
    __tablename__ = "icon"

    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    s3_path: Mapped[str | None] = mapped_column(Text)
    content_type: Mapped[str | None] = mapped_column(Text)
    file_size: Mapped[int | None] = mapped_column(Integer)
    uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
