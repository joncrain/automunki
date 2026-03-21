import uuid
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.api.deps import get_session
from automunki.core.security import current_optional_user
from automunki.models.client import ClientInstallReport
from automunki.models.munki import Catalog, PkgInfo, PkgInfoCatalog
from automunki.models.user import User
from automunki.schemas.common import PaginatedResponse
from automunki.schemas.munki import (
    CatalogAssignment,
    PkgInfoRead,
    PkgInfoSummary,
    PkgInfoUpdate,
    PromoteRequest,
)
from automunki.services.audit import create_audit_entry
from automunki.services.munki import compile_pkginfo_plist
from automunki.services.promotion import promote_pkginfo

router = APIRouter(prefix="/pkginfo", tags=["pkginfo"])

INSTALL_REPORT_TIMELINE_DAYS = 90


def _to_summary(pkg: PkgInfo) -> dict:
    return {
        "id": pkg.id,
        "name": pkg.name,
        "display_name": pkg.display_name,
        "version": pkg.version,
        "category": pkg.category,
        "developer": pkg.developer,
        "catalog_names": [c.name for c in pkg.catalogs],
        "unattended_install": pkg.unattended_install,
        "unattended_uninstall": pkg.unattended_uninstall,
        "minimum_os_version": pkg.minimum_os_version,
        "installer_type": pkg.installer_type,
        "restart_action": pkg.restart_action,
        "created_at": pkg.created_at,
        "updated_at": pkg.updated_at,
    }


def _to_read(pkg: PkgInfo) -> dict:
    data = {
        "id": pkg.id,
        "name": pkg.name,
        "version": pkg.version,
        "display_name": pkg.display_name,
        "description": pkg.description,
        "category": pkg.category,
        "developer": pkg.developer,
        "icon_name": pkg.icon_name,
        "installer_item_location": pkg.installer_item_location,
        "installer_item_hash": pkg.installer_item_hash,
        "installer_item_size": pkg.installer_item_size,
        "installed_size": pkg.installed_size,
        "installer_type": pkg.installer_type,
        "minimum_os_version": pkg.minimum_os_version,
        "maximum_os_version": pkg.maximum_os_version,
        "uninstall_method": pkg.uninstall_method,
        "unattended_install": pkg.unattended_install,
        "unattended_uninstall": pkg.unattended_uninstall,
        "autoremove": pkg.autoremove,
        "uninstallable": pkg.uninstallable,
        "installs": pkg.installs,
        "receipts": pkg.receipts,
        "blocking_applications": pkg.blocking_applications,
        "items_to_copy": pkg.items_to_copy,
        "supported_architectures": pkg.supported_architectures,
        "requires": pkg.requires,
        "update_for": pkg.update_for,
        "preinstall_script": pkg.preinstall_script,
        "postinstall_script": pkg.postinstall_script,
        "preuninstall_script": pkg.preuninstall_script,
        "postuninstall_script": pkg.postuninstall_script,
        "installcheck_script": pkg.installcheck_script,
        "uninstallcheck_script": pkg.uninstallcheck_script,
        "version_script": pkg.version_script,
        "notes": pkg.notes,
        "restart_action": pkg.restart_action,
        "on_demand": pkg.on_demand,
        "force_install_after_date": pkg.force_install_after_date,
        "apple_item": pkg.apple_item,
        "installable_condition": pkg.installable_condition,
        "package_path": pkg.package_path,
        "package_complete_url": pkg.package_complete_url,
        "minimum_munki_version": pkg.minimum_munki_version,
        "uninstaller_item_location": pkg.uninstaller_item_location,
        "catalog_names": [c.name for c in pkg.catalogs],
        "is_deleted": pkg.is_deleted,
        "created_at": pkg.created_at,
        "updated_at": pkg.updated_at,
    }
    return data


@router.get("", response_model=PaginatedResponse)
async def list_pkginfo(
    session: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str | None = None,
    catalog: str | None = None,
    category: str | None = None,
    name: str | None = None,
    sort_by: str = "name",
    sort_order: str = "asc",
):
    query = select(PkgInfo).where(PkgInfo.is_deleted.is_(False))

    if search:
        query = query.where(PkgInfo.name.ilike(f"%{search}%") | PkgInfo.display_name.ilike(f"%{search}%"))
    if category:
        query = query.where(PkgInfo.category == category)
    if name:
        query = query.where(PkgInfo.name == name)
    if catalog:
        query = query.join(PkgInfoCatalog).join(Catalog).where(Catalog.name == catalog)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_query)).scalar() or 0

    sort_col = getattr(PkgInfo, sort_by, PkgInfo.name)
    query = query.order_by(sort_col.asc() if sort_order == "asc" else sort_col.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    query = query.options(selectinload(PkgInfo.catalogs))

    result = await session.execute(query)
    items = [PkgInfoSummary(**_to_summary(p)) for p in result.scalars().unique().all()]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/categories", response_model=list[str])
async def list_categories(
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(PkgInfo.category)
        .where(PkgInfo.is_deleted.is_(False), PkgInfo.category.isnot(None))
        .distinct()
        .order_by(PkgInfo.category)
    )
    return [row[0] for row in result.all()]


@router.get("/{pkg_id}", response_model=PkgInfoRead)
async def get_pkginfo(
    pkg_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(PkgInfo).options(selectinload(PkgInfo.catalogs)).where(PkgInfo.id == pkg_id))
    pkg = result.scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="PkgInfo not found")
    return PkgInfoRead(**_to_read(pkg))


@router.get("/{pkg_id}/plist")
async def get_pkginfo_plist(
    pkg_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(PkgInfo).options(selectinload(PkgInfo.catalogs)).where(PkgInfo.id == pkg_id))
    pkg = result.scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="PkgInfo not found")
    plist_data = await compile_pkginfo_plist(pkg)
    return Response(content=plist_data, media_type="application/xml")


@router.get("/{pkg_id}/install-reports/summary")
async def pkginfo_install_reports_summary(
    pkg_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Counts by status, distinct machines, and daily install events for this pkginfo name."""
    result = await session.execute(select(PkgInfo).where(PkgInfo.id == pkg_id))
    pkg = result.scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="PkgInfo not found")

    name = pkg.name

    total_reports = (
        await session.scalar(
            select(func.count()).select_from(ClientInstallReport).where(ClientInstallReport.item_name == name)
        )
    ) or 0

    unique_machines = (
        await session.scalar(
            select(func.count(func.distinct(ClientInstallReport.machine_id)))
            .select_from(ClientInstallReport)
            .where(ClientInstallReport.item_name == name)
        )
    ) or 0

    status_rows = (
        await session.execute(
            select(ClientInstallReport.status, func.count())
            .where(ClientInstallReport.item_name == name)
            .group_by(ClientInstallReport.status)
        )
    ).all()
    by_status = {row[0]: int(row[1]) for row in status_rows}

    event_ts = func.coalesce(ClientInstallReport.install_date, ClientInstallReport.created_at)
    cutoff = datetime.now(UTC) - timedelta(days=INSTALL_REPORT_TIMELINE_DAYS - 1)
    day_trunc = func.date_trunc("day", event_ts)
    timeline_rows = (
        await session.execute(
            select(day_trunc, func.count(ClientInstallReport.id))
            .where(ClientInstallReport.item_name == name)
            .where(event_ts >= cutoff)
            .group_by(day_trunc)
            .order_by(day_trunc)
        )
    ).all()

    counts: dict[date, int] = {}
    for dt, cnt in timeline_rows:
        if isinstance(dt, datetime):
            d = dt.astimezone(UTC).date()
        else:
            d = dt  # pragma: no cover
        counts[d] = int(cnt)

    end = datetime.now(UTC).date()
    start = end - timedelta(days=INSTALL_REPORT_TIMELINE_DAYS - 1)
    series: list[dict[str, int | str]] = []
    cur = start
    while cur <= end:
        series.append({"date": cur.isoformat(), "count": counts.get(cur, 0)})
        cur += timedelta(days=1)

    return {
        "item_name": name,
        "total_reports": total_reports,
        "unique_machines": unique_machines,
        "by_status": by_status,
        "timeline": series,
    }


@router.put("/{pkg_id}", response_model=PkgInfoRead)
async def update_pkginfo(
    pkg_id: uuid.UUID,
    data: PkgInfoUpdate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    result = await session.execute(select(PkgInfo).options(selectinload(PkgInfo.catalogs)).where(PkgInfo.id == pkg_id))
    pkg = result.scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="PkgInfo not found")

    before = _to_read(pkg)
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(pkg, field, value)

    await create_audit_entry(
        session,
        action="update",
        entity_type="pkg_info",
        entity_id=str(pkg_id),
        entity_name=f"{pkg.name} {pkg.version}",
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        before_snapshot=before,
        after_snapshot=_to_read(pkg),
        changes=update_data,
    )

    await session.commit()
    await session.refresh(pkg)
    return PkgInfoRead(**_to_read(pkg))


@router.delete("/{pkg_id}")
async def delete_pkginfo(
    pkg_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    pkg = await session.get(PkgInfo, pkg_id)
    if not pkg:
        raise HTTPException(status_code=404, detail="PkgInfo not found")

    pkg.is_deleted = True
    await create_audit_entry(
        session,
        action="delete",
        entity_type="pkg_info",
        entity_id=str(pkg_id),
        entity_name=f"{pkg.name} {pkg.version}",
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )
    await session.commit()
    return {"message": "PkgInfo deleted"}


@router.put("/{pkg_id}/catalogs", response_model=PkgInfoRead)
async def update_pkginfo_catalogs(
    pkg_id: uuid.UUID,
    data: CatalogAssignment,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    result = await session.execute(select(PkgInfo).options(selectinload(PkgInfo.catalogs)).where(PkgInfo.id == pkg_id))
    pkg = result.scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="PkgInfo not found")

    before_names = [c.name for c in pkg.catalogs]

    await session.execute(PkgInfoCatalog.__table__.delete().where(PkgInfoCatalog.pkg_info_id == pkg_id))
    await session.flush()

    for cat_name in data.catalog_names:
        cat_result = await session.execute(select(Catalog).where(Catalog.name == cat_name))
        cat = cat_result.scalar_one_or_none()
        if cat:
            session.add(PkgInfoCatalog(pkg_info_id=pkg_id, catalog_id=cat.id))

    await create_audit_entry(
        session,
        action="update",
        entity_type="pkg_info",
        entity_id=str(pkg_id),
        entity_name=f"{pkg.name} {pkg.version}",
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        changes={"catalog_names": {"before": before_names, "after": data.catalog_names}},
    )

    await session.commit()
    await session.refresh(pkg)
    result = await session.execute(select(PkgInfo).options(selectinload(PkgInfo.catalogs)).where(PkgInfo.id == pkg_id))
    pkg = result.scalar_one_or_none()
    return PkgInfoRead(**_to_read(pkg))


@router.post("/{pkg_id}/promote")
async def promote_pkg(
    pkg_id: uuid.UUID,
    data: PromoteRequest,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    success = await promote_pkginfo(
        session,
        pkg_info_id=pkg_id,
        target_catalog_id=data.target_catalog_id,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )
    if not success:
        raise HTTPException(status_code=404, detail="PkgInfo or catalog not found")
    await session.commit()
    return {"message": "Promoted successfully"}
