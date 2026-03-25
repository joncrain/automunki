"""Munki plist generation and catalog compilation service."""

import plistlib
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.models.munki import (
    Catalog,
    Manifest,
    ManifestCatalog,
    ManifestInclusion,
    PkgInfo,
    PkgInfoCatalog,
)


async def compile_catalog_plist(session: AsyncSession, catalog_id) -> bytes:
    """Generate a Munki catalog plist from all PkgInfo entries in a catalog.

    Matches the behaviour of Munki's ``makecatalogs``: ``notes`` and all
    keys starting with ``_`` (e.g. ``_metadata``) are stripped from each
    pkginfo dict before the catalog is written.

    Entries are always built from normalized DB columns (not ``raw_plist``) so
    edits in the UI/API are reflected immediately.
    """
    result = await session.execute(
        select(PkgInfo)
        .options(selectinload(PkgInfo.catalogs))
        .join(PkgInfoCatalog, PkgInfo.id == PkgInfoCatalog.pkg_info_id)
        .where(PkgInfoCatalog.catalog_id == catalog_id)
        .where(PkgInfo.is_deleted.is_(False))
    )
    pkg_infos = result.scalars().all()

    catalog_items = []
    for pkg in pkg_infos:
        catalog_items.append(_strip_catalog_keys(_pkginfo_to_dict(pkg, for_catalog=True)))

    return plistlib.dumps(catalog_items)


async def compile_manifest_plist(session: AsyncSession, manifest_id) -> bytes:
    """Generate a Munki manifest plist from the DB."""
    result = await session.execute(
        select(Manifest)
        .options(
            selectinload(Manifest.catalog_refs).selectinload(ManifestCatalog.catalog),
            selectinload(Manifest.items),
            selectinload(Manifest.included_manifests).selectinload(ManifestInclusion.child),
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
    """Generate a pkginfo plist from a PkgInfo model.

    Always serializes from normalized columns so the download matches catalogs
    and the software detail API.
    """
    return plistlib.dumps(_pkginfo_to_dict(pkg_info))


def sync_pkginfo_raw_plist(pkg: PkgInfo) -> None:
    """Set ``raw_plist`` to a snapshot of the current columns (JSONB-friendly).

    Import paths may still store an original plist; any update should refresh
    this so database inspection and exports stay aligned with editable fields.
    """
    pkg.raw_plist = _pkginfo_to_dict(pkg, for_catalog=False)


def _strip_catalog_keys(d: dict) -> dict:
    """Remove ``notes`` and underscore-prefixed keys from a pkginfo dict.

    This mirrors what Munki's ``makecatalogs`` does before writing each
    pkginfo entry into a catalog file.
    """
    d.pop("notes", None)
    for key in [k for k in d if k.startswith("_")]:
        del d[key]
    return d


def _pkginfo_to_dict(pkg: PkgInfo, *, for_catalog: bool = False) -> dict:
    """Convert a PkgInfo model to a plist-compatible dict.

    When *for_catalog* is True the output matches what Munki clients
    expect inside a catalog (no ``notes``, no ``_metadata``).
    """
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
        ("version_script", "version_script"),
        ("notes", "notes"),
        ("RestartAction", "restart_action"),
        ("installable_condition", "installable_condition"),
        ("package_path", "package_path"),
        ("PackageCompleteURL", "package_complete_url"),
        ("minimum_munki_version", "minimum_munki_version"),
        ("uninstaller_item_location", "uninstaller_item_location"),
        ("force_install_after_date", "force_install_after_date"),
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
        ("OnDemand", "on_demand"),
        ("apple_item", "apple_item"),
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

    if not for_catalog and pkg.metadata_:
        d["_metadata"] = pkg.metadata_

    return d


async def get_catalog_by_name(session: AsyncSession, catalog_name: str) -> Catalog | None:
    """Look up a Catalog by its unique name."""
    result = await session.execute(select(Catalog).where(Catalog.name == catalog_name))
    return result.scalar_one_or_none()


async def get_catalog_last_modified(session: AsyncSession, catalog_id) -> datetime | None:
    """Return the most recent updated_at of any PkgInfo in a catalog."""
    result = await session.execute(
        select(func.max(PkgInfo.updated_at))
        .join(PkgInfoCatalog, PkgInfo.id == PkgInfoCatalog.pkg_info_id)
        .where(PkgInfoCatalog.catalog_id == catalog_id)
        .where(PkgInfo.is_deleted.is_(False))
    )
    return result.scalar_one_or_none()


async def get_manifest_by_name(session: AsyncSession, manifest_name: str) -> Manifest | None:
    """Look up a Manifest by its unique name."""
    result = await session.execute(select(Manifest).where(Manifest.name == manifest_name))
    return result.scalar_one_or_none()


async def compile_icon_hashes_plist(_session: AsyncSession) -> bytes:
    """Generate the _icon_hashes.plist used by Munki to check icon freshness.

    Returns an empty mapping; icon URLs are served via ``MUNKI_REPO_ICON_BASE_URL`` redirects.
    """
    return plistlib.dumps({})
