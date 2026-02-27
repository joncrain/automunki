"""Munki plist generation and catalog compilation service."""

import plistlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.models.munki import (
    Manifest,
    ManifestCatalog,
    ManifestInclusion,
    PkgInfo,
    PkgInfoCatalog,
)


async def compile_catalog_plist(session: AsyncSession, catalog_id) -> bytes:
    """Generate a Munki catalog plist from all PkgInfo entries in a catalog."""
    result = await session.execute(
        select(PkgInfo)
        .join(PkgInfoCatalog, PkgInfo.id == PkgInfoCatalog.pkg_info_id)
        .where(PkgInfoCatalog.catalog_id == catalog_id)
        .where(PkgInfo.is_deleted.is_(False))
    )
    pkg_infos = result.scalars().all()

    catalog_items = []
    for pkg in pkg_infos:
        if pkg.raw_plist:
            catalog_items.append(pkg.raw_plist)
        else:
            catalog_items.append(_pkginfo_to_dict(pkg))

    return plistlib.dumps(catalog_items)


async def compile_manifest_plist(session: AsyncSession, manifest_id) -> bytes:
    """Generate a Munki manifest plist from the DB."""
    result = await session.execute(
        select(Manifest)
        .options(
            selectinload(Manifest.catalog_refs).selectinload(ManifestCatalog.catalog),
            selectinload(Manifest.items),
            selectinload(Manifest.included_manifests).selectinload(
                ManifestInclusion.child
            ),
        )
        .where(Manifest.id == manifest_id)
    )
    manifest = result.scalar_one_or_none()
    if not manifest:
        return b""

    plist_dict: dict = {}

    catalogs = sorted(manifest.catalog_refs, key=lambda c: c.sort_order)
    plist_dict["catalogs"] = [cr.catalog.name for cr in catalogs]

    item_type_map: dict[str, list[str]] = {}
    for item in sorted(manifest.items, key=lambda i: i.sort_order):
        item_type_map.setdefault(item.item_type.value, []).append(item.item_name)

    for item_type in [
        "managed_installs",
        "managed_uninstalls",
        "managed_updates",
        "optional_installs",
        "featured_items",
        "default_installs",
    ]:
        if item_type in item_type_map:
            plist_dict[item_type] = item_type_map[item_type]

    inclusions = sorted(manifest.included_manifests, key=lambda i: i.sort_order)
    plist_dict["included_manifests"] = [inc.child.name for inc in inclusions]

    if manifest.conditional_items:
        plist_dict["conditional_items"] = manifest.conditional_items

    return plistlib.dumps(plist_dict)


async def compile_pkginfo_plist(pkg_info: PkgInfo) -> bytes:
    """Generate a pkginfo plist from a PkgInfo model."""
    if pkg_info.raw_plist:
        return plistlib.dumps(pkg_info.raw_plist)
    return plistlib.dumps(_pkginfo_to_dict(pkg_info))


def _pkginfo_to_dict(pkg: PkgInfo) -> dict:
    """Convert a PkgInfo model to a plist-compatible dict."""
    d: dict = {
        "name": pkg.name,
        "version": pkg.version,
    }

    simple_fields = [
        ("display_name", "display_name"),
        ("description", "description"),
        ("category", "category"),
        ("developer", "developer"),
        ("icon_name", "icon_name"),
        ("installer_item_location", "installer_item_location"),
        ("installer_item_hash", "installer_item_hash"),
        ("installer_item_size", "installer_item_size"),
        ("installed_size", "installed_size"),
        ("installer_type", "installer_type"),
        ("minimum_os_version", "minimum_os_version"),
        ("maximum_os_version", "maximum_os_version"),
        ("uninstall_method", "uninstall_method"),
        ("preinstall_script", "preinstall_script"),
        ("postinstall_script", "postinstall_script"),
        ("preuninstall_script", "preuninstall_script"),
        ("postuninstall_script", "postuninstall_script"),
        ("installcheck_script", "installcheck_script"),
        ("uninstallcheck_script", "uninstallcheck_script"),
    ]

    for plist_key, attr in simple_fields:
        val = getattr(pkg, attr, None)
        if val is not None:
            d[plist_key] = val

    bool_fields = [
        ("autoremove", "autoremove"),
        ("unattended_install", "unattended_install"),
        ("unattended_uninstall", "unattended_uninstall"),
        ("uninstallable", "uninstallable"),
    ]
    for plist_key, attr in bool_fields:
        val = getattr(pkg, attr, None)
        if val is not None:
            d[plist_key] = val

    json_fields = [
        ("installs", "installs"),
        ("receipts", "receipts"),
        ("blocking_applications", "blocking_applications"),
        ("items_to_copy", "items_to_copy"),
        ("supported_architectures", "supported_architectures"),
        ("requires", "requires"),
        ("update_for", "update_for"),
    ]
    for plist_key, attr in json_fields:
        val = getattr(pkg, attr, None)
        if val is not None:
            d[plist_key] = val

    if pkg.catalogs:
        d["catalogs"] = [c.name for c in pkg.catalogs]

    if pkg.metadata_:
        d["_metadata"] = pkg.metadata_

    return d
