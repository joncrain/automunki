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


def post_json(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
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

    recipe_name = os.path.basename(report_path).replace(".plist", "")
    identifier = f"local.munki.{recipe_name}"

    if imported_items:
        for item in imported_items:
            catalogs = item.get("catalogs", "")
            if isinstance(catalogs, str):
                catalogs = [c.strip() for c in catalogs.split(",") if c.strip()]

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
