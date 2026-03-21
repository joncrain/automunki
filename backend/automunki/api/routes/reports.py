import uuid
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.api.deps import get_session
from automunki.models.client import ClientInstallReport, ClientMachine, ClientMachineCheckin
from automunki.schemas.common import PaginatedResponse
from automunki.services.apple_device_image import apple_fmip_device_image_url

router = APIRouter(prefix="/reports", tags=["reports"])

CHECKIN_CHART_DAYS = 90


async def _checkin_chart_data(
    session: AsyncSession,
    machine_id: uuid.UUID,
    days: int = CHECKIN_CHART_DAYS,
) -> tuple[list[dict[str, int | str]], int]:
    """Daily check-in counts for chart, and total check-ins (all time)."""
    total = (
        await session.scalar(
            select(func.count()).select_from(ClientMachineCheckin).where(ClientMachineCheckin.machine_id == machine_id)
        )
        or 0
    )

    cutoff = datetime.now(UTC) - timedelta(days=days - 1)
    day_trunc = func.date_trunc("day", ClientMachineCheckin.checked_in_at)
    result = await session.execute(
        select(day_trunc, func.count(ClientMachineCheckin.id))
        .where(ClientMachineCheckin.machine_id == machine_id)
        .where(ClientMachineCheckin.checked_in_at >= cutoff)
        .group_by(day_trunc)
        .order_by(day_trunc)
    )
    rows = result.all()

    counts: dict[date, int] = {}
    for dt, cnt in rows:
        if isinstance(dt, datetime):
            d = dt.astimezone(UTC).date()
        else:
            d = dt  # pragma: no cover
        counts[d] = int(cnt)

    end = datetime.now(UTC).date()
    start = end - timedelta(days=days - 1)
    series: list[dict[str, int | str]] = []
    cur = start
    while cur <= end:
        series.append({"date": cur.isoformat(), "count": counts.get(cur, 0)})
        cur += timedelta(days=1)

    return series, int(total)


def _coerce_install_date(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


@router.post("/checkin")
async def client_checkin(
    data: dict,
    session: AsyncSession = Depends(get_session),
):
    """Receive a check-in from a managed Mac."""
    serial = data.get("serial_number")
    if not serial:
        raise HTTPException(status_code=400, detail="serial_number required")

    result = await session.execute(select(ClientMachine).where(ClientMachine.serial_number == serial))
    machine = result.scalar_one_or_none()

    now = datetime.now(UTC)

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
        machine.client_identifier = data.get("client_identifier", machine.client_identifier)
        machine.hardware_info = data.get("hardware_info", machine.hardware_info)
        machine.installed_software = data.get("installed_software", machine.installed_software)
        machine.last_checkin_at = now
        machine.os_build = data.get("os_build", machine.os_build)
        machine.cpu_arch = data.get("cpu_arch", machine.cpu_arch)
        machine.physical_cpus = data.get("physical_cpus", machine.physical_cpus)
        machine.logical_cpus = data.get("logical_cpus", machine.logical_cpus)
    else:
        machine = ClientMachine(
            serial_number=serial,
            hostname=data.get("hostname"),
            os_version=data.get("os_version"),
            os_build=data.get("os_build"),
            machine_model=data.get("machine_model"),
            cpu_type=data.get("cpu_type"),
            cpu_arch=data.get("cpu_arch"),
            physical_cpus=data.get("physical_cpus"),
            logical_cpus=data.get("logical_cpus"),
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

    session.add(ClientMachineCheckin(machine_id=machine.id, checked_in_at=now))

    # Replace rows for this check-in so repeated agent runs do not duplicate history.
    if "install_results" in data:
        await session.execute(delete(ClientInstallReport).where(ClientInstallReport.machine_id == machine.id))
        for install_result in data.get("install_results") or []:
            report = ClientInstallReport(
                machine_id=machine.id,
                item_name=install_result.get("item_name", ""),
                item_version=install_result.get("item_version"),
                status=install_result.get("status", "unknown"),
                install_date=_coerce_install_date(install_result.get("install_date")),
                error_message=install_result.get("error_message"),
                details=install_result if isinstance(install_result, dict) else None,
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
            ClientMachine.hostname.ilike(f"%{search}%") | ClientMachine.serial_number.ilike(f"%{search}%")
        )

    count = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0

    result = await session.execute(
        query.order_by(ClientMachine.last_checkin_at.desc().nullslast()).offset((page - 1) * page_size).limit(page_size)
    )
    machines = result.scalars().all()

    report_counts: dict = {}
    if machines:
        ids = [m.id for m in machines]
        count_rows = (
            await session.execute(
                select(ClientInstallReport.machine_id, func.count(ClientInstallReport.id))
                .where(ClientInstallReport.machine_id.in_(ids))
                .group_by(ClientInstallReport.machine_id)
            )
        ).all()
        report_counts = {row[0]: row[1] for row in count_rows}

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
                "last_checkin_at": m.last_checkin_at.isoformat() if m.last_checkin_at else None,
                "disk_free_gb": m.disk_free_gb,
                "install_report_count": report_counts.get(m.id, 0),
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
    result = await session.execute(select(ClientMachine).where(ClientMachine.id == uuid.UUID(machine_id)))
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

    hw = machine.hardware_info if isinstance(machine.hardware_info, dict) else {}
    product_name = hw.get("product_name")
    if isinstance(product_name, str):
        product_name = product_name.strip() or None
    else:
        product_name = None

    puuid = hw.get("platform_uuid")
    platform_uuid = puuid.strip() if isinstance(puuid, str) and puuid.strip() else None

    device_image_url = apple_fmip_device_image_url(
        machine.serial_number,
        machine.machine_model,
        machine.hardware_info if isinstance(machine.hardware_info, dict) else None,
    )

    checkin_history, checkin_total = await _checkin_chart_data(session, machine.id)

    return {
        "id": str(machine.id),
        "serial_number": machine.serial_number,
        "hostname": machine.hostname,
        "product_name": product_name,
        "device_image_url": device_image_url,
        "platform_uuid": platform_uuid,
        "os_version": machine.os_version,
        "os_build": machine.os_build,
        "machine_model": machine.machine_model,
        "cpu_type": machine.cpu_type,
        "cpu_arch": machine.cpu_arch,
        "physical_cpus": machine.physical_cpus,
        "logical_cpus": machine.logical_cpus,
        "ram_mb": machine.ram_mb,
        "disk_size_gb": machine.disk_size_gb,
        "disk_free_gb": machine.disk_free_gb,
        "munki_version": machine.munki_version,
        "manifest_name": machine.manifest_name,
        "client_identifier": machine.client_identifier,
        "hardware_info": machine.hardware_info,
        "installed_software": machine.installed_software,
        "last_checkin_at": machine.last_checkin_at.isoformat() if machine.last_checkin_at else None,
        "first_checkin_at": machine.first_checkin_at.isoformat() if machine.first_checkin_at else None,
        "checkin_total": checkin_total,
        "checkin_history": checkin_history,
        "install_reports": [
            {
                "id": str(r.id),
                "item_name": r.item_name,
                "item_version": r.item_version,
                "status": r.status,
                "error_message": r.error_message,
                "install_date": r.install_date.isoformat() if r.install_date else None,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports.scalars().all()
        ],
    }


@router.get("/installs")
async def list_install_reports(
    session: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str | None = None,
    status: str | None = Query(None, description="Filter by install row status (e.g. installed, failed)"),
    item_name: str | None = Query(None, description="Exact Munki item name (pkginfo name)"),
):
    """Paginated `client_install_report` rows with machine hostname/serial."""
    conditions = []
    if item_name:
        conditions.append(ClientInstallReport.item_name == item_name)
    if search:
        term = f"%{search}%"
        conditions.append(
            or_(
                ClientInstallReport.item_name.ilike(term),
                ClientMachine.hostname.ilike(term),
                ClientMachine.serial_number.ilike(term),
            )
        )
    if status:
        conditions.append(ClientInstallReport.status == status)

    count_q = select(func.count(ClientInstallReport.id)).select_from(ClientInstallReport).join(ClientMachine)
    if conditions:
        count_q = count_q.where(*conditions)
    total = (await session.execute(count_q)).scalar() or 0

    list_q = (
        select(ClientInstallReport, ClientMachine.hostname, ClientMachine.serial_number)
        .join(ClientMachine, ClientInstallReport.machine_id == ClientMachine.id)
        .order_by(ClientInstallReport.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    if conditions:
        list_q = list_q.where(*conditions)

    list_result = await session.execute(list_q)
    rows = list_result.all()

    return PaginatedResponse(
        items=[
            {
                "id": str(report.id),
                "machine_id": str(report.machine_id),
                "hostname": host,
                "serial_number": serial,
                "item_name": report.item_name,
                "item_version": report.item_version,
                "status": report.status,
                "error_message": report.error_message,
                "install_date": report.install_date.isoformat() if report.install_date else None,
                "created_at": report.created_at.isoformat(),
            }
            for report, host, serial in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/compliance")
async def compliance_overview(
    session: AsyncSession = Depends(get_session),
):
    """Fleet compliance overview."""
    total = (await session.execute(select(func.count()).select_from(ClientMachine))).scalar() or 0

    from datetime import timedelta

    recent_cutoff = datetime.now(UTC) - timedelta(days=7)
    recent = (
        await session.execute(
            select(func.count()).select_from(ClientMachine).where(ClientMachine.last_checkin_at >= recent_cutoff)
        )
    ).scalar() or 0

    stale_cutoff = datetime.now(UTC) - timedelta(days=30)
    stale = (
        await session.execute(
            select(func.count()).select_from(ClientMachine).where(ClientMachine.last_checkin_at < stale_cutoff)
        )
    ).scalar() or 0

    return {
        "total_machines": total,
        "checked_in_last_7_days": recent,
        "stale_over_30_days": stale,
        "compliance_percentage": round((recent / total * 100) if total > 0 else 0, 1),
    }
