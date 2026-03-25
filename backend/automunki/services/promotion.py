"""Promotion engine for moving pkginfo between catalogs."""

import uuid
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.models.munki import (
    Catalog,
    PkgInfo,
    PkgInfoCatalog,
    PromotionRule,
    PromotionStrategy,
)
from automunki.services.audit import create_audit_entry
from automunki.services.munki import sync_pkginfo_raw_plist

logger = structlog.get_logger()


async def promote_pkginfo(
    session: AsyncSession,
    *,
    pkg_info_id: uuid.UUID,
    target_catalog_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
    user_email: str | None = None,
) -> bool:
    """Promote a PkgInfo to a target catalog."""
    pkg = await session.get(PkgInfo, pkg_info_id)
    if not pkg:
        return False

    target_catalog = await session.get(Catalog, target_catalog_id)
    if not target_catalog:
        return False

    existing = await session.execute(
        select(PkgInfoCatalog).where(
            PkgInfoCatalog.pkg_info_id == pkg_info_id,
            PkgInfoCatalog.catalog_id == target_catalog_id,
        )
    )
    if existing.scalar_one_or_none():
        return True

    before_catalogs = [c.name for c in pkg.catalogs]

    session.add(PkgInfoCatalog(pkg_info_id=pkg_info_id, catalog_id=target_catalog_id))

    await session.flush()
    pkg_sync = (
        await session.execute(select(PkgInfo).options(selectinload(PkgInfo.catalogs)).where(PkgInfo.id == pkg_info_id))
    ).scalar_one()
    sync_pkginfo_raw_plist(pkg_sync)

    after_catalogs = [c.name for c in pkg_sync.catalogs]
    await create_audit_entry(
        session,
        action="promote",
        entity_type="pkg_info",
        entity_id=str(pkg_info_id),
        entity_name=f"{pkg.name} {pkg.version}",
        user_id=user_id,
        user_email=user_email,
        before_snapshot={"catalogs": before_catalogs},
        after_snapshot={"catalogs": after_catalogs},
        notes=f"Promoted to {target_catalog.name}",
    )

    await session.flush()
    logger.info(
        "pkginfo_promoted",
        pkg_name=pkg.name,
        version=pkg.version,
        target_catalog=target_catalog.name,
    )
    return True


async def check_auto_promotions(session: AsyncSession) -> list[dict]:
    """Check and execute time-based auto-promotions."""
    result = await session.execute(
        select(PromotionRule).where(
            PromotionRule.strategy == PromotionStrategy.auto_time,
            PromotionRule.auto_promote_days.isnot(None),
        )
    )
    rules = result.scalars().all()
    promoted = []

    for rule in rules:
        cutoff = datetime.now(UTC) - timedelta(days=rule.auto_promote_days)
        pkg_result = await session.execute(
            select(PkgInfo)
            .join(PkgInfoCatalog, PkgInfo.id == PkgInfoCatalog.pkg_info_id)
            .where(
                PkgInfoCatalog.catalog_id == rule.source_catalog_id,
                PkgInfo.name == rule.pkginfo_name,
                PkgInfo.is_deleted.is_(False),
                PkgInfo.created_at <= cutoff,
            )
        )
        eligible = pkg_result.scalars().all()

        for pkg in eligible:
            already = await session.execute(
                select(PkgInfoCatalog).where(
                    PkgInfoCatalog.pkg_info_id == pkg.id,
                    PkgInfoCatalog.catalog_id == rule.target_catalog_id,
                )
            )
            if already.scalar_one_or_none():
                continue

            success = await promote_pkginfo(
                session,
                pkg_info_id=pkg.id,
                target_catalog_id=rule.target_catalog_id,
                user_email="system:auto-promotion",
            )
            if success:
                promoted.append(
                    {
                        "name": pkg.name,
                        "version": pkg.version,
                        "target_catalog_id": str(rule.target_catalog_id),
                    }
                )

    return promoted
