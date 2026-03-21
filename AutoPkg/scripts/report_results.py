"""Process an AutoPkg report plist: report results to the API and ingest pkginfo.

Expected environment variables:
    API_BASE_URL  - e.g. https://example.ngrok-free.app
    RUN_ID        - UUID of the AutoPkg run
    REPORT_FILE   - path to the report plist
    PKGSINFO_DIR  - path to the pkgsinfo directory
"""

import json
import os
import plistlib
import re
import sys
import urllib.request
from datetime import date, datetime


def make_serializable(obj):
    """Recursively convert plist-native types to JSON-safe equivalents."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [make_serializable(v) for v in obj]
    return obj


def imported_display_title(item, pkgsinfo_dir, recipe_name):
    """Human-facing title for approvals UI (pkg display name, not report filename)."""
    name = item.get("display_name") or item.get("name")
    if name:
        return str(name)
    pkginfo_path = item.get("pkginfo_path", "")
    if pkginfo_path and pkgsinfo_dir:
        full_path = os.path.join(pkgsinfo_dir, pkginfo_path)
        if os.path.exists(full_path):
            with open(full_path, "rb") as pf:
                pkginfo_dict = plistlib.load(pf)
            return str(
                pkginfo_dict.get("display_name")
                or pkginfo_dict.get("name")
                or recipe_name
            )
    return recipe_name


def _json_headers():
    h = {"Content-Type": "application/json"}
    token = os.environ.get("AUTOMUNKI_API_TOKEN", "")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _report_stem(report_path: str) -> str:
    base = os.path.basename(report_path)
    if base.lower().endswith(".plist"):
        return base[:-6]
    return base


def _identifier_from_report_plist(report: dict) -> str | None:
    """Best-effort recipe Identifier from report body (runner / AutoPkg variants)."""
    for key in ("Identifier", "identifier", "recipe_identifier"):
        v = report.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    rec = report.get("recipe")
    if isinstance(rec, dict):
        v = rec.get("Identifier") or rec.get("identifier")
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _find_identifier_deep(obj: object, depth: int = 0) -> str | None:
    """Walk report plist; AutoPkg often nests Identifier under summary/input dicts."""
    if depth > 14:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("Identifier", "identifier") and isinstance(v, str):
                s = v.strip()
                if s.startswith("local.munki.") or s.startswith("com.github."):
                    return s
                if s.startswith("com.") and s.count(".") >= 3:
                    return s
            found = _find_identifier_deep(v, depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_identifier_deep(v, depth + 1)
            if found:
                return found
    return None


def _recipe_file_from_cloud_runner_report_name(report_path: str) -> str | None:
    """``report_YYMMDD_HHMM_Recipe.munki.recipe.plist`` → ``Recipe.munki.recipe``."""
    base = os.path.basename(report_path)
    m = re.match(r"^report_\d+_\d+_(.+)\.plist$", base, re.IGNORECASE)
    return m.group(1) if m else None


def recipe_identifier_and_name(report_path: str, report: dict) -> tuple[str, str]:
    """
    (recipe_identifier, recipe_name) for API / DB matching.

    Report files are often named like ``local.munki.Blender.plist`` (full identifier).
    The old logic always prepended ``local.munki.``, producing a bogus identifier and
    breaking ``last_run_*`` updates on the recipe row.
    """
    stem = _report_stem(report_path)
    ident = _identifier_from_report_plist(report) or _find_identifier_deep(report)
    if ident:
        if ident.startswith("local.munki."):
            name = ident[len("local.munki.") :]
        else:
            name = stem
        return ident, name
    cr_recipe = _recipe_file_from_cloud_runner_report_name(report_path)
    if cr_recipe and cr_recipe.endswith(".munki.recipe"):
        product = cr_recipe[: -len(".munki.recipe")]
        return f"local.munki.{product}", product
    if stem.startswith("local.munki."):
        return stem, stem[len("local.munki.") :]
    if stem.startswith("com."):
        return stem, stem.split(".")[-1]
    return f"local.munki.{stem}", stem


def post_json(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers=_json_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode()), resp.status
    except Exception as e:
        print(f"  POST {url} failed: {e}")
        return None, 0


def main():
    api_base = os.environ["API_BASE_URL"] + "/api/v1/autopkg"
    run_id = os.environ["RUN_ID"]
    report_path = os.environ.get("REPORT_FILE", "")
    pkgsinfo_dir = os.environ.get("PKGSINFO_DIR", "")

    if not report_path or not os.path.exists(report_path):
        print(f"Report not found: {report_path}")
        sys.exit(0)

    with open(report_path, "rb") as f:
        report = plistlib.load(f)

    failures = report.get("failures", [])
    summary = report.get("summary_results", {})
    munki_summary = summary.get("munki_importer_summary_result", {})
    imported_items = munki_summary.get("data_rows", [])

    identifier, recipe_name = recipe_identifier_and_name(report_path, report)

    if imported_items:
        for item in imported_items:
            catalogs = item.get("catalogs", "")
            if isinstance(catalogs, str):
                catalogs = [
                    c.strip() for c in re.split(r"[,/|]+", catalogs) if c.strip()
                ]

            result_payload = {
                "recipe_identifier": identifier,
                "recipe_name": recipe_name,
                "status": "imported",
                "imported_version": item.get("version"),
                "imported_display_name": imported_display_title(
                    item, pkgsinfo_dir, recipe_name
                ),
                "imported_pkg_path": item.get("pkg_repo_path"),
                "imported_pkginfo_path": item.get("pkginfo_path"),
                "imported_catalogs": catalogs,
            }
            _, status = post_json(
                f"{api_base}/runs/{run_id}/results", result_payload
            )
            print(
                f"  Reported imported: {item.get('name')} "
                f"{item.get('version')} ({status})"
            )

            pkginfo_path = item.get("pkginfo_path", "")
            if pkginfo_path and pkgsinfo_dir:
                full_path = os.path.join(pkgsinfo_dir, pkginfo_path)
                if os.path.exists(full_path):
                    with open(full_path, "rb") as pf:
                        pkginfo_dict = plistlib.load(pf)
                    serializable = make_serializable(pkginfo_dict)
                    resp_body, status = post_json(
                        f"{api_base}/pkginfo/ingest",
                        {"pkginfo": serializable},
                    )
                    if resp_body and resp_body.get("skipped"):
                        print(
                            f"  Pkginfo already in DB: "
                            f"{item.get('name')} {item.get('version')}"
                        )
                    elif status == 200:
                        print(
                            f"  Ingested pkginfo: "
                            f"{item.get('name')} {item.get('version')}"
                        )
                    else:
                        print(f"  Pkginfo ingest response: {resp_body}")
                else:
                    print(f"  Pkginfo file not found at {full_path}")

    elif failures:
        error_msg = "; ".join(
            f.get("message", "") for f in failures if isinstance(f, dict)
        )
        post_json(
            f"{api_base}/runs/{run_id}/results",
            {
                "recipe_identifier": identifier,
                "recipe_name": recipe_name,
                "status": "failed",
                "error_message": error_msg,
            },
        )
        print(f"  Reported failed: {recipe_name}")
    else:
        post_json(
            f"{api_base}/runs/{run_id}/results",
            {
                "recipe_identifier": identifier,
                "recipe_name": recipe_name,
                "status": "no_change",
            },
        )
        print(f"  Reported no_change: {recipe_name}")


if __name__ == "__main__":
    main()
