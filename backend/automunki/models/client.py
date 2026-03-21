import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from automunki.models.base import Base, UUIDMixin


class ClientMachine(UUIDMixin, Base):
    __tablename__ = "client_machine"

    serial_number: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(Text, index=True)
    os_version: Mapped[str | None] = mapped_column(Text)
    os_build: Mapped[str | None] = mapped_column(Text)
    machine_model: Mapped[str | None] = mapped_column(Text)
    cpu_type: Mapped[str | None] = mapped_column(Text)
    cpu_arch: Mapped[str | None] = mapped_column(Text)
    physical_cpus: Mapped[int | None] = mapped_column(Integer)
    logical_cpus: Mapped[int | None] = mapped_column(Integer)
    ram_mb: Mapped[int | None] = mapped_column(Integer)
    disk_size_gb: Mapped[int | None] = mapped_column(Integer)
    disk_free_gb: Mapped[int | None] = mapped_column(Integer)

    munki_version: Mapped[str | None] = mapped_column(Text)
    manifest_name: Mapped[str | None] = mapped_column(Text, index=True)
    client_identifier: Mapped[str | None] = mapped_column(Text)

    hardware_info: Mapped[dict | None] = mapped_column(JSONB)
    installed_software: Mapped[dict | None] = mapped_column(JSONB)

    last_checkin_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    first_checkin_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    install_reports: Mapped[list["ClientInstallReport"]] = relationship(
        back_populates="machine", cascade="all, delete-orphan", lazy="selectin"
    )
    checkins: Mapped[list["ClientMachineCheckin"]] = relationship(
        back_populates="machine", cascade="all, delete-orphan", lazy="noload"
    )


class ClientMachineCheckin(UUIDMixin, Base):
    __tablename__ = "client_machine_checkin"

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("client_machine.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    checked_in_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    machine: Mapped["ClientMachine"] = relationship(back_populates="checkins")


class ClientInstallReport(UUIDMixin, Base):
    __tablename__ = "client_install_report"

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("client_machine.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    item_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    item_version: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    install_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    machine: Mapped["ClientMachine"] = relationship(back_populates="install_reports")
