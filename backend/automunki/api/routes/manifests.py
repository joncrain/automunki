import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from automunki.api.deps import get_session
from automunki.core.security import current_optional_user
from automunki.models.munki import (
    Catalog,
    ItemType,
    Manifest,
    ManifestCatalog,
    ManifestInclusion,
    ManifestItem,
)
from automunki.models.user import User
from automunki.schemas.munki import (
    ManifestCreate,
    ManifestRead,
    ManifestUpdate,
    conditional_items_for_storage,
)
from automunki.services.audit import create_audit_entry
from automunki.services.munki import compile_manifest_plist

router = APIRouter(prefix="/manifests", tags=["manifests"])


def _manifest_to_read(m: Manifest) -> dict:
    catalog_names = sorted([cr.catalog.name for cr in m.catalog_refs], key=lambda n: n)

    items_by_type: dict[str, list[str]] = {}
    for item in sorted(m.items, key=lambda i: i.sort_order):
        items_by_type.setdefault(item.item_type.value, []).append(item.item_name)

    included = sorted(m.included_manifests, key=lambda i: i.sort_order)

    return {
        "id": m.id,
        "name": m.name,
        "display_name": m.display_name,
        "notes": m.notes,
        "conditional_items": m.conditional_items,
        "catalog_names": catalog_names,
        "managed_installs": items_by_type.get("managed_installs", []),
        "managed_uninstalls": items_by_type.get("managed_uninstalls", []),
        "managed_updates": items_by_type.get("managed_updates", []),
        "optional_installs": items_by_type.get("optional_installs", []),
        "featured_items": items_by_type.get("featured_items", []),
        "default_installs": items_by_type.get("default_installs", []),
        "included_manifest_names": [inc.child.name for inc in included],
        "created_at": m.created_at,
        "updated_at": m.updated_at,
    }


async def _load_manifest(session: AsyncSession, manifest_id: uuid.UUID):
    result = await session.execute(
        select(Manifest)
        .options(
            selectinload(Manifest.catalog_refs).selectinload(ManifestCatalog.catalog),
            selectinload(Manifest.items),
            selectinload(Manifest.included_manifests).selectinload(ManifestInclusion.child),
        )
        .where(Manifest.id == manifest_id)
    )
    return result.scalar_one_or_none()


@router.get("", response_model=list[ManifestRead])
async def list_manifests(session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(Manifest)
        .options(
            selectinload(Manifest.catalog_refs).selectinload(ManifestCatalog.catalog),
            selectinload(Manifest.items),
            selectinload(Manifest.included_manifests).selectinload(ManifestInclusion.child),
        )
        .order_by(Manifest.name)
    )
    manifests = result.scalars().unique().all()
    return [ManifestRead(**_manifest_to_read(m)) for m in manifests]


@router.get("/{manifest_id}", response_model=ManifestRead)
async def get_manifest(
    manifest_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    m = await _load_manifest(session, manifest_id)
    if not m:
        raise HTTPException(status_code=404, detail="Manifest not found")
    return ManifestRead(**_manifest_to_read(m))


@router.get("/{manifest_id}/compile")
async def compile_manifest(
    manifest_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    plist_data = await compile_manifest_plist(session, manifest_id)
    if not plist_data:
        raise HTTPException(status_code=404, detail="Manifest not found")
    return Response(content=plist_data, media_type="application/xml")


@router.post("", response_model=ManifestRead)
async def create_manifest(
    data: ManifestCreate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    existing = await session.execute(select(Manifest).where(Manifest.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Manifest already exists")

    manifest = Manifest(
        name=data.name,
        display_name=data.display_name,
        notes=data.notes,
        conditional_items=conditional_items_for_storage(data.conditional_items),
    )
    session.add(manifest)
    await session.flush()

    await _sync_manifest_relations(session, manifest, data)

    await create_audit_entry(
        session,
        action="create",
        entity_type="manifest",
        entity_id=str(manifest.id),
        entity_name=manifest.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        after_snapshot=data.model_dump(),
    )

    await session.commit()
    m = await _load_manifest(session, manifest.id)
    return ManifestRead(**_manifest_to_read(m))


@router.put("/{manifest_id}", response_model=ManifestRead)
async def update_manifest(
    manifest_id: uuid.UUID,
    data: ManifestUpdate,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    m = await _load_manifest(session, manifest_id)
    if not m:
        raise HTTPException(status_code=404, detail="Manifest not found")

    before = _manifest_to_read(m)

    patch = data.model_dump(exclude_unset=True)

    if "name" in patch:
        new_name = (data.name or "").strip()
        if not new_name:
            raise HTTPException(status_code=422, detail="Manifest name cannot be empty")
        if new_name != m.name:
            existing = await session.execute(select(Manifest).where(Manifest.name == new_name))
            other = existing.scalar_one_or_none()
            if other is not None and other.id != m.id:
                raise HTTPException(status_code=409, detail="Manifest name already exists")
            m.name = new_name

    if "display_name" in patch:
        m.display_name = data.display_name

    if "notes" in patch:
        m.notes = data.notes

    if "conditional_items" in patch:
        m.conditional_items = conditional_items_for_storage(data.conditional_items)

    await _sync_manifest_relations(session, m, data)

    await create_audit_entry(
        session,
        action="update",
        entity_type="manifest",
        entity_id=str(manifest_id),
        entity_name=m.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        before_snapshot=before,
        after_snapshot=data.model_dump(exclude_unset=True),
    )

    await session.commit()
    m = await _load_manifest(session, manifest_id)
    return ManifestRead(**_manifest_to_read(m))


@router.delete("/{manifest_id}")
async def delete_manifest(
    manifest_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    m = await session.get(Manifest, manifest_id)
    if not m:
        raise HTTPException(status_code=404, detail="Manifest not found")

    await create_audit_entry(
        session,
        action="delete",
        entity_type="manifest",
        entity_id=str(manifest_id),
        entity_name=m.name,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )

    await session.delete(m)
    await session.commit()
    return {"message": "Manifest deleted"}


async def _sync_manifest_relations(session, manifest, data):
    """Sync catalog refs, items, and inclusions from create/update data."""
    if hasattr(data, "catalog_names") and data.catalog_names is not None:
        await session.execute(delete(ManifestCatalog).where(ManifestCatalog.manifest_id == manifest.id))
        await session.flush()

        for i, cat_name in enumerate(data.catalog_names):
            cat_result = await session.execute(select(Catalog).where(Catalog.name == cat_name))
            cat = cat_result.scalar_one_or_none()
            if cat:
                session.add(
                    ManifestCatalog(
                        manifest_id=manifest.id,
                        catalog_id=cat.id,
                        sort_order=i,
                    )
                )

    item_type_fields = {
        "managed_installs": ItemType.managed_installs,
        "managed_uninstalls": ItemType.managed_uninstalls,
        "managed_updates": ItemType.managed_updates,
        "optional_installs": ItemType.optional_installs,
        "featured_items": ItemType.featured_items,
        "default_installs": ItemType.default_installs,
    }

    has_item_updates = any(getattr(data, field, None) is not None for field in item_type_fields)

    if has_item_updates:
        for field_name, item_type in item_type_fields.items():
            if getattr(data, field_name, None) is not None:
                await session.execute(
                    delete(ManifestItem).where(
                        ManifestItem.manifest_id == manifest.id,
                        ManifestItem.item_type == item_type,
                    )
                )
        await session.flush()

        for field_name, item_type in item_type_fields.items():
            names = getattr(data, field_name, None)
            if names is not None:
                for i, name in enumerate(names):
                    session.add(
                        ManifestItem(
                            manifest_id=manifest.id,
                            item_name=name,
                            item_type=item_type,
                            sort_order=i,
                        )
                    )

    included_names = getattr(data, "included_manifest_names", None)
    if included_names is not None:
        await session.execute(delete(ManifestInclusion).where(ManifestInclusion.parent_manifest_id == manifest.id))
        await session.flush()

        for i, inc_name in enumerate(included_names):
            inc_result = await session.execute(select(Manifest).where(Manifest.name == inc_name))
            inc_manifest = inc_result.scalar_one_or_none()
            if inc_manifest:
                session.add(
                    ManifestInclusion(
                        parent_manifest_id=manifest.id,
                        child_manifest_id=inc_manifest.id,
                        sort_order=i,
                    )
                )

    await session.flush()
