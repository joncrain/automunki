from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class CatalogBase(BaseModel):
    name: str
    display_name: str | None = None
    description: str | None = None
    is_production: bool = False
    sort_order: int = 0


class CatalogCreate(CatalogBase):
    pass


class CatalogUpdate(BaseModel):
    display_name: str | None = None
    description: str | None = None
    is_production: bool | None = None
    sort_order: int | None = None


class CatalogRead(CatalogBase):
    id: UUID
    created_at: datetime
    item_count: int = 0

    model_config = {"from_attributes": True}


class PkgInfoBase(BaseModel):
    name: str
    version: str
    display_name: str | None = None
    description: str | None = None
    category: str | None = None
    developer: str | None = None
    icon_name: str | None = None
    installer_item_location: str | None = None
    installer_item_hash: str | None = None
    installer_item_size: int | None = None
    installed_size: int | None = None
    installer_type: str | None = None
    minimum_os_version: str | None = None
    maximum_os_version: str | None = None
    uninstall_method: str | None = None
    unattended_install: bool = False
    unattended_uninstall: bool = False
    autoremove: bool = False
    uninstallable: bool = True
    installs: list | None = None
    receipts: list | None = None
    blocking_applications: list | None = None
    items_to_copy: list | None = None
    supported_architectures: list | None = None
    requires: list | None = None
    update_for: list | None = None
    preinstall_script: str | None = None
    postinstall_script: str | None = None
    preuninstall_script: str | None = None
    postuninstall_script: str | None = None
    installcheck_script: str | None = None
    uninstallcheck_script: str | None = None
    version_script: str | None = None
    notes: str | None = None
    restart_action: str | None = None
    on_demand: bool = False
    force_install_after_date: str | None = None
    apple_item: bool = False
    installable_condition: str | None = None
    package_path: str | None = None
    package_complete_url: str | None = None
    minimum_munki_version: str | None = None
    uninstaller_item_location: str | None = None


class PkgInfoCreate(PkgInfoBase):
    catalog_names: list[str] = []


class PkgInfoUpdate(BaseModel):
    display_name: str | None = None
    description: str | None = None
    category: str | None = None
    developer: str | None = None
    icon_name: str | None = None
    minimum_os_version: str | None = None
    maximum_os_version: str | None = None
    uninstall_method: str | None = None
    unattended_install: bool | None = None
    unattended_uninstall: bool | None = None
    autoremove: bool | None = None
    uninstallable: bool | None = None
    installs: list | None = None
    receipts: list | None = None
    blocking_applications: list | None = None
    items_to_copy: list | None = None
    supported_architectures: list | None = None
    requires: list | None = None
    update_for: list | None = None
    preinstall_script: str | None = None
    postinstall_script: str | None = None
    preuninstall_script: str | None = None
    postuninstall_script: str | None = None
    installcheck_script: str | None = None
    uninstallcheck_script: str | None = None
    version_script: str | None = None
    notes: str | None = None
    restart_action: str | None = None
    on_demand: bool | None = None
    force_install_after_date: str | None = None
    apple_item: bool | None = None
    installable_condition: str | None = None
    package_path: str | None = None
    package_complete_url: str | None = None
    minimum_munki_version: str | None = None
    installer_type: str | None = None
    installed_size: int | None = None
    uninstaller_item_location: str | None = None


class PkgInfoRead(PkgInfoBase):
    id: UUID
    catalog_names: list[str] = []
    is_deleted: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PkgInfoSummary(BaseModel):
    id: UUID
    name: str
    display_name: str | None = None
    version: str
    category: str | None = None
    developer: str | None = None
    catalog_names: list[str] = []
    unattended_install: bool = False
    unattended_uninstall: bool = False
    minimum_os_version: str | None = None
    installer_type: str | None = None
    restart_action: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CatalogAssignment(BaseModel):
    catalog_names: list[str]


class PromoteRequest(BaseModel):
    target_catalog_id: UUID


class ManifestItemRead(BaseModel):
    id: UUID
    item_name: str
    item_type: str
    sort_order: int = 0

    model_config = {"from_attributes": True}


class ManifestCatalogRead(BaseModel):
    catalog_id: UUID
    catalog_name: str
    sort_order: int = 0

    model_config = {"from_attributes": True}


class ManifestBase(BaseModel):
    name: str
    display_name: str | None = None
    notes: str | None = None
    conditional_items: dict | None = None


class ManifestCreate(ManifestBase):
    catalog_names: list[str] = []
    managed_installs: list[str] = []
    managed_uninstalls: list[str] = []
    managed_updates: list[str] = []
    optional_installs: list[str] = []
    featured_items: list[str] = []
    default_installs: list[str] = []
    included_manifest_names: list[str] = []


class ManifestUpdate(BaseModel):
    display_name: str | None = None
    notes: str | None = None
    conditional_items: dict | None = None
    catalog_names: list[str] | None = None
    managed_installs: list[str] | None = None
    managed_uninstalls: list[str] | None = None
    managed_updates: list[str] | None = None
    optional_installs: list[str] | None = None
    featured_items: list[str] | None = None
    default_installs: list[str] | None = None
    included_manifest_names: list[str] | None = None


class ManifestRead(ManifestBase):
    id: UUID
    catalog_names: list[str] = []
    managed_installs: list[str] = []
    managed_uninstalls: list[str] = []
    managed_updates: list[str] = []
    optional_installs: list[str] = []
    featured_items: list[str] = []
    default_installs: list[str] = []
    included_manifest_names: list[str] = []
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PromotionRuleBase(BaseModel):
    pkginfo_name: str
    source_catalog_id: UUID
    target_catalog_id: UUID
    strategy: str = "manual"
    auto_promote_days: int | None = None
    requires_approval: bool = True


class PromotionRuleCreate(PromotionRuleBase):
    pass


class PromotionRuleRead(PromotionRuleBase):
    id: UUID
    created_at: datetime

    model_config = {"from_attributes": True}
