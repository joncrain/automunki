from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from automunki.schemas.munki import (
    ConditionalItemBlock,
    ManifestRead,
    ManifestUpdate,
    conditional_items_for_storage,
)


def test_conditional_items_nested_storage_shape() -> None:
    inner = ConditionalItemBlock(condition="os_vers_major >= 14")
    outer = ConditionalItemBlock(
        condition='machine_type == "laptop"',
        managed_installs=["Foo"],
        conditional_items=[inner],
    )
    stored = conditional_items_for_storage([outer])
    assert stored is not None
    assert stored[0]["managed_installs"] == ["Foo"]
    assert stored[0]["conditional_items"][0]["condition"] == "os_vers_major >= 14"


def test_conditional_item_block_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        ConditionalItemBlock(condition="x == 1", not_a_munki_key=[])  # type: ignore[call-arg]


def test_manifest_update_coerces_top_level_dict_to_none() -> None:
    m = ManifestUpdate(conditional_items={"condition": "bad"})  # type: ignore[arg-type]
    assert m.conditional_items is None


def test_manifest_update_empty_list_to_none() -> None:
    m = ManifestUpdate(conditional_items=[])
    assert m.conditional_items is None


def test_manifest_read_accepts_list_of_blocks() -> None:
    now = datetime.now(UTC)
    mid = uuid4()
    mr = ManifestRead(
        id=mid,
        name="site_default",
        display_name=None,
        notes=None,
        conditional_items=[
            ConditionalItemBlock(
                condition='arch == "arm64"',
                optional_installs=["Bar"],
            )
        ],
        catalog_names=[],
        managed_installs=[],
        managed_uninstalls=[],
        managed_updates=[],
        optional_installs=[],
        featured_items=[],
        default_installs=[],
        included_manifest_names=[],
        created_at=now,
        updated_at=now,
    )
    assert mr.conditional_items is not None
    assert mr.conditional_items[0].optional_installs == ["Bar"]
