"""Canonical page keys for RBAC (aligned with frontend sidebar routes)."""

from enum import StrEnum


class PageKey(StrEnum):
    overview = "overview"
    munki_software = "munki.software"
    munki_manifests = "munki.manifests"
    munki_catalogs = "munki.catalogs"
    autopkg_runs = "autopkg.runs"
    autopkg_recipes = "autopkg.recipes"
    autopkg_discover = "autopkg.discover"
    autopkg_approvals = "autopkg.approvals"
    reporting_devices = "reporting.devices"
    reporting_installs = "reporting.installs"
    admin_audit = "admin.audit"
    admin_settings = "admin.settings"
    admin_access = "admin.access"


ALL_PAGE_KEYS: frozenset[str] = frozenset(x.value for x in PageKey)


def api_path_to_page_key(path: str) -> str | None:
    """Map HTTP request path (e.g. ``/api/v1/pkginfo``) to a PageKey. ``None`` = no RBAC (auth routes)."""
    raw = path.rstrip("/") or "/"
    if "/api/v1/" in raw:
        rest = raw.split("/api/v1/", 1)[1]
    elif raw.startswith("/api/v1"):
        rest = raw[len("/api/v1") :].lstrip("/")
    else:
        return PageKey.overview

    if not rest:
        return PageKey.overview

    seg = rest.split("/")
    root = seg[0]

    if root == "auth":
        return None

    if root == "users":
        if len(seg) > 1 and seg[1] == "me":
            return None
        return PageKey.admin_access

    if root == "rbac":
        return PageKey.admin_access

    if root in ("pkginfo", "icons"):
        return PageKey.munki_software
    if root == "manifests":
        return PageKey.munki_manifests
    if root == "catalogs":
        return PageKey.munki_catalogs

    if root == "reports":
        if len(seg) > 1 and seg[1] == "installs":
            return PageKey.reporting_installs
        return PageKey.reporting_devices

    if root == "audit":
        return PageKey.admin_audit
    if root == "settings":
        return PageKey.admin_settings

    if root == "autopkg":
        if len(seg) < 2:
            return PageKey.autopkg_runs
        second = seg[1]
        if second == "runs":
            return PageKey.autopkg_runs
        if second == "approvals":
            return PageKey.autopkg_approvals
        if second == "results":
            return PageKey.autopkg_approvals
        if second == "metadata-cache":
            return PageKey.autopkg_recipes
        if second == "recipes":
            if len(seg) > 2 and seg[2] == "discover":
                return PageKey.autopkg_discover
            # trust / approve flows on recipes → approvals page
            if len(seg) >= 4 and seg[3] in (
                "approve-trust",
                "verify-trust",
                "update-trust",
            ):
                return PageKey.autopkg_approvals
            return PageKey.autopkg_recipes
        if second in ("cache", "repos", "github"):
            return PageKey.autopkg_discover
        return PageKey.autopkg_runs

    return PageKey.overview
