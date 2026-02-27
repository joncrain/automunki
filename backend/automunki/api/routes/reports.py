from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.api.deps import get_session
from automunki.models.client import ClientInstallReport, ClientMachine
from automunki.schemas.common import PaginatedResponse

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/checkin")
async def client_checkin(
    data: dict,
    session: AsyncSession = Depends(get_session),
):
    """Receive a check-in from a managed Mac."""
    serial = data.get("serial_number")
    if not serial:
        return {"error": "serial_number required"}

    result = await session.execute(
        select(ClientMachine).where(ClientMachine.serial_number == serial)
    )
    machine = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)

    if machine:
        machine.hostname = data.get("hostname", machine.hostname)
        machine.os_version = data.get("os_version", machine.os_version)
        machine.machine_model = data.get("machine_model", machine.machine_model)
        machine.cpu_type = data.get("cpu_type", machine.cpu_type)
        machine.ram_mb = data.get("ram_mb", machine.ram_mb)
        machine.disk_size_gb = data.get("disk_size_gb", machine.disk_size_gb)
        machine.disk_free_gb = data.get("disk_free_gb", machine.disk_free_gb)
        machine.munki_version = data.get("munki_version", machine.munki_version)
        machine.manifest_name = data.get("manifest_name", machine.manifest_name)
        machine.client_identifier = data.get(
            "client_identifier", machine.client_identifier
        )
        machine.hardware_info = data.get("hardware_info", machine.hardware_info)
        machine.installed_software = data.get(
            "installed_software", machine.installed_software
        )
        machine.last_checkin_at = now
    else:
        machine = ClientMachine(
            serial_number=serial,
            hostname=data.get("hostname"),
            os_version=data.get("os_version"),
            machine_model=data.get("machine_model"),
            cpu_type=data.get("cpu_type"),
            ram_mb=data.get("ram_mb"),
            disk_size_gb=data.get("disk_size_gb"),
            disk_free_gb=data.get("disk_free_gb"),
            munki_version=data.get("munki_version"),
            manifest_name=data.get("manifest_name"),
            client_identifier=data.get("client_identifier"),
            hardware_info=data.get("hardware_info"),
            installed_software=data.get("installed_software"),
            first_checkin_at=now,
            last_checkin_at=now,
        )
        session.add(machine)
        await session.flush()

    for install_result in data.get("install_results", []):
        report = ClientInstallReport(
            machine_id=machine.id,
            item_name=install_result.get("item_name", ""),
            item_version=install_result.get("item_version"),
            status=install_result.get("status", "unknown"),
            error_message=install_result.get("error_message"),
            details=install_result,
        )
        session.add(report)

    await session.commit()
    return {"status": "ok", "serial_number": serial}


@router.get("/machines")
async def list_machines(
    session: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str | None = None,
):
    query = select(ClientMachine)
    if search:
        query = query.where(
            ClientMachine.hostname.ilike(f"%{search}%")
            | ClientMachine.serial_number.ilike(f"%{search}%")
        )

    count = (
        await session.execute(select(func.count()).select_from(query.subquery()))
    ).scalar() or 0

    result = await session.execute(
        query.order_by(ClientMachine.last_checkin_at.desc().nullslast())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    machines = result.scalars().all()

    return PaginatedResponse(
        items=[
            {
                "id": str(m.id),
                "serial_number": m.serial_number,
                "hostname": m.hostname,
                "os_version": m.os_version,
                "machine_model": m.machine_model,
                "munki_version": m.munki_version,
                "manifest_name": m.manifest_name,
                "last_checkin_at": m.last_checkin_at.isoformat()
                if m.last_checkin_at
                else None,
                "disk_free_gb": m.disk_free_gb,
            }
            for m in machines
        ],
        total=count,
        page=page,
        page_size=page_size,
        total_pages=(count + page_size - 1) // page_size,
    )


@router.get("/machines/{machine_id}")
async def get_machine(
    machine_id: str,
    session: AsyncSession = Depends(get_session),
):
    import uuid

    result = await session.execute(
        select(ClientMachine).where(ClientMachine.id == uuid.UUID(machine_id))
    )
    machine = result.scalar_one_or_none()
    if not machine:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Machine not found")

    reports = await session.execute(
        select(ClientInstallReport)
        .where(ClientInstallReport.machine_id == machine.id)
        .order_by(ClientInstallReport.created_at.desc())
        .limit(100)
    )

    return {
        "id": str(machine.id),
        "serial_number": machine.serial_number,
        "hostname": machine.hostname,
        "os_version": machine.os_version,
        "os_build": machine.os_build,
        "machine_model": machine.machine_model,
        "cpu_type": machine.cpu_type,
        "ram_mb": machine.ram_mb,
        "disk_size_gb": machine.disk_size_gb,
        "disk_free_gb": machine.disk_free_gb,
        "munki_version": machine.munki_version,
        "manifest_name": machine.manifest_name,
        "client_identifier": machine.client_identifier,
        "hardware_info": machine.hardware_info,
        "installed_software": machine.installed_software,
        "last_checkin_at": machine.last_checkin_at.isoformat()
        if machine.last_checkin_at
        else None,
        "first_checkin_at": machine.first_checkin_at.isoformat()
        if machine.first_checkin_at
        else None,
        "install_reports": [
            {
                "id": str(r.id),
                "item_name": r.item_name,
                "item_version": r.item_version,
                "status": r.status,
                "error_message": r.error_message,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports.scalars().all()
        ],
    }


@router.get("/compliance")
async def compliance_overview(
    session: AsyncSession = Depends(get_session),
):
    """Fleet compliance overview."""
    total = (
        await session.execute(select(func.count()).select_from(ClientMachine))
    ).scalar() or 0

    from datetime import timedelta

    recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent = (
        await session.execute(
            select(func.count())
            .select_from(ClientMachine)
            .where(ClientMachine.last_checkin_at >= recent_cutoff)
        )
    ).scalar() or 0

    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stale = (
        await session.execute(
            select(func.count())
            .select_from(ClientMachine)
            .where(ClientMachine.last_checkin_at < stale_cutoff)
        )
    ).scalar() or 0

    return {
        "total_machines": total,
        "checked_in_last_7_days": recent,
        "stale_over_30_days": stale,
        "compliance_percentage": round((recent / total * 100) if total > 0 else 0, 1),
    }
