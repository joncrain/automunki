import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.api.deps import get_session
from automunki.core.security import current_optional_user
from automunki.models.munki import Catalog, PkgInfo, PkgInfoCatalog
from automunki.models.user import User
from automunki.schemas.munki import (
    CatalogCreate,
    CatalogRead,
    CatalogUpdate,
    PkgInfoSummary,
)
from automunki.services.audit import create_audit_entry
from automunki.services.munki import compile_catalog_plist

router = APIRouter(prefix="/catalogs", tags=["catalogs"])


@router.get("", response_model=list[CatalogRead])
async def list_catalogs(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Catalog).order_by(Catalog.sort_order))
    catalogs = result.scalars().all()

    response = []
    for cat in catalogs:
        count_result = await session.execute(
            select(func.count())
            .select_from(PkgInfoCatalog)
            .join(PkgInfo, PkgInfo.id == PkgInfoCatalog.pkg_info_id)
            .where(
                PkgInfoCatalog.catalog_id == cat.id,
                PkgInfo.is_deleted.is_(False),
            )
        )
        count = count_result.scalar() or 0
        response.append(
            CatalogRead(
                id=cat.id,
                name=cat.name,
                display_name=cat.display_name,
                description=cat.description,
                is_production=cat.is_production,
                sort_order=cat.sort_order,
                created_at=cat.created_at,
                item_count=count,
            )
        )
    return response


@router.post("/makecatalogs")
async def makecatalogs(
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    """Rebuild all Munki catalogs from pkginfo in the database.

    DB-backed equivalent of Munki's ``makecatalogs``: previews compiled plist
    sizes and surfaces common issues (empty catalogs, missing installer paths).
    """
    catalogs_result = await session.execute(select(Catalog).order_by(Catalog.sort_order))
    catalogs = catalogs_result.scalars().all()

    warnings: list[str] = []
    catalog_summary: list[dict] = []

    for cat in catalogs:
        count_result = await session.execute(
            select(func.count())
            .select_from(PkgInfoCatalog)
            .join(PkgInfo, PkgInfo.id == PkgInfoCatalog.pkg_info_id)
            .where(
                PkgInfoCatalog.catalog_id == cat.id,
                PkgInfo.is_deleted.is_(False),
            )
        )
        item_count = count_result.scalar() or 0

        if item_count == 0:
            warnings.append(f"Catalog '{cat.name}' is empty")

        missing_location = await session.execute(
            select(PkgInfo.name, PkgInfo.version)
            .join(PkgInfoCatalog, PkgInfo.id == PkgInfoCatalog.pkg_info_id)
            .where(
                PkgInfoCatalog.catalog_id == cat.id,
                PkgInfo.is_deleted.is_(False),
                PkgInfo.installer_item_location.is_(None),
                PkgInfo.installer_type.notin_(["nopkg", "apple_update_metadata"]),
            )
        )
        for name, version in missing_location.all():
            warnings.append(f"{name}-{version} in '{cat.name}' is missing installer_item_location")

        plist_bytes = await compile_catalog_plist(session, cat.id)

        catalog_summary.append(
            {
                "name": cat.name,
                "item_count": item_count,
                "plist_bytes": len(plist_bytes),
            }
        )

    await create_audit_entry(
        session,
        action="makecatalogs",
        entity_type="catalog",
        entity_id="makecatalogs",
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )
    await session.commit()

    return {
        "catalogs": catalog_summary,
        "warnings": warnings,
        "total_catalogs": len(catalog_summary),
    }


@router.post("", response_model=CatalogRead)
async def create_catalog(
    data: CatalogCreate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    existing = await session.execute(select(Catalog).where(Catalog.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Catalog already exists")

    catalog = Catalog(**data.model_dump())
    session.add(catalog)
    await session.flush()

    await create_audit_entry(
        session,
        action="create",
        entity_type="catalog",
        entity_id=str(catalog.id),
        entity_name=catalog.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        after_snapshot=data.model_dump(),
    )

    await session.commit()
    return CatalogRead(
        id=catalog.id,
        name=catalog.name,
        display_name=catalog.display_name,
        description=catalog.description,
        is_production=catalog.is_production,
        sort_order=catalog.sort_order,
        created_at=catalog.created_at,
        item_count=0,
    )


@router.put("/{catalog_id}", response_model=CatalogRead)
async def update_catalog(
    catalog_id: uuid.UUID,
    data: CatalogUpdate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    catalog = await session.get(Catalog, catalog_id)
    if not catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(catalog, field, value)

    await create_audit_entry(
        session,
        action="update",
        entity_type="catalog",
        entity_id=str(catalog_id),
        entity_name=catalog.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        changes=update_data,
    )

    await session.commit()
    return CatalogRead(
        id=catalog.id,
        name=catalog.name,
        display_name=catalog.display_name,
        description=catalog.description,
        is_production=catalog.is_production,
        sort_order=catalog.sort_order,
        created_at=catalog.created_at,
        item_count=0,
    )


@router.delete("/{catalog_id}")
async def delete_catalog(
    catalog_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    catalog = await session.get(Catalog, catalog_id)
    if not catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")

    item_count = (
        await session.execute(
            select(func.count()).select_from(PkgInfoCatalog).where(PkgInfoCatalog.catalog_id == catalog_id)
        )
    ).scalar() or 0

    if item_count > 0:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete catalog with {item_count} assigned items. Remove items first.",
        )

    await create_audit_entry(
        session,
        action="delete",
        entity_type="catalog",
        entity_id=str(catalog_id),
        entity_name=catalog.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )

    await session.delete(catalog)
    await session.commit()
    return {"message": "Catalog deleted"}


@router.get("/{catalog_id}/items", response_model=list[PkgInfoSummary])
async def list_catalog_items(
    catalog_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(PkgInfo)
        .join(PkgInfoCatalog)
        .where(
            PkgInfoCatalog.catalog_id == catalog_id,
            PkgInfo.is_deleted.is_(False),
        )
        .options(selectinload(PkgInfo.catalogs))
        .order_by(PkgInfo.name)
    )
    items = result.scalars().unique().all()
    return [
        PkgInfoSummary(
            id=p.id,
            name=p.name,
            display_name=p.display_name,
            version=p.version,
            category=p.category,
            developer=p.developer,
            catalog_names=[c.name for c in p.catalogs],
            unattended_install=p.unattended_install,
            created_at=p.created_at,
            updated_at=p.updated_at,
        )
        for p in items
    ]


@router.post("/{catalog_id}/compile")
async def compile_catalog(
    catalog_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    catalog = await session.get(Catalog, catalog_id)
    if not catalog:
        raise HTTPException(status_code=404, detail="Catalog not found")

    plist_data = await compile_catalog_plist(session, catalog_id)
    return Response(content=plist_data, media_type="application/xml")
