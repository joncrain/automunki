#!/usr/bin/env python3
"""AutoMunki Client Agent - collects inventory and Munki status, reports to the API.

Install on managed Macs and run via launchd after Munki check-ins.
"""

import json
import os
import plistlib
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("requests library required: pip3 install requests")
    sys.exit(1)

API_URL = os.environ.get("AUTOMUNKI_API_URL", "")
CONFIG_PATH = "/etc/automunki/agent.conf"

MANAGED_INSTALLS_DIR = "/Library/Managed Installs"
APPLICATION_INVENTORY = os.path.join(MANAGED_INSTALLS_DIR, "ApplicationInventory.plist")
INSTALL_RESULTS = os.path.join(
    MANAGED_INSTALLS_DIR, "Logs", "ManagedSoftwareUpdate.log"
)
MUNKI_REPORT = os.path.join(MANAGED_INSTALLS_DIR, "ManagedInstallReport.plist")
CLIENT_PREFS = "/Library/Preferences/ManagedInstalls.plist"


def load_config():
    """Load agent configuration from file or environment."""
    config = {"api_url": API_URL}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            config.update(json.load(f))
    if not config.get("api_url"):
        print(
            "No API URL configured. Set AUTOMUNKI_API_URL or configure /etc/automunki/agent.conf"
        )
        sys.exit(1)
    return config


def get_serial_number():
    result = subprocess.run(
        ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"],
        capture_output=True,
        text=True,
    )
    for line in result.stdout.split("\n"):
        if "IOPlatformSerialNumber" in line:
            return line.split('"')[-2]
    return "UNKNOWN"


def get_hardware_info():
    info = {
        "hostname": platform.node(),
        "os_version": platform.mac_ver()[0],
        "machine_model": "",
        "cpu_type": platform.processor(),
    }

    sp_result = subprocess.run(
        ["system_profiler", "SPHardwareDataType", "-json"],
        capture_output=True,
        text=True,
    )
    try:
        sp_data = json.loads(sp_result.stdout)
        hw = sp_data.get("SPHardwareDataType", [{}])[0]
        info["machine_model"] = hw.get("machine_model", "")
        info["ram_mb"] = _parse_memory(hw.get("physical_memory", ""))
    except (json.JSONDecodeError, IndexError, KeyError):
        pass

    disk_result = subprocess.run(
        ["df", "-g", "/"],
        capture_output=True,
        text=True,
    )
    try:
        lines = disk_result.stdout.strip().split("\n")
        if len(lines) > 1:
            parts = lines[1].split()
            info["disk_size_gb"] = int(parts[1])
            info["disk_free_gb"] = int(parts[3])
    except (IndexError, ValueError):
        pass

    return info


def _parse_memory(mem_str):
    """Parse memory string like '16 GB' to MB."""
    try:
        parts = mem_str.split()
        val = int(parts[0])
        if "GB" in mem_str.upper():
            return val * 1024
        return val
    except (IndexError, ValueError):
        return None


def get_munki_info():
    """Get Munki client configuration."""
    info = {"munki_version": "", "manifest_name": "", "client_identifier": ""}

    munki_version_result = subprocess.run(
        [
            "defaults",
            "read",
            "/Library/Preferences/ManagedInstalls",
            "InstallAppleSoftwareUpdates",
        ],
        capture_output=True,
        text=True,
    )

    version_plist = Path("/usr/local/munki/munkilib/version.plist")
    if version_plist.exists():
        with open(version_plist, "rb") as f:
            try:
                vdata = plistlib.load(f)
                info["munki_version"] = vdata.get("CFBundleShortVersionString", "")
            except Exception:
                pass

    if os.path.exists(CLIENT_PREFS):
        try:
            result = subprocess.run(
                ["defaults", "read", CLIENT_PREFS, "ClientIdentifier"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                info["client_identifier"] = result.stdout.strip()
        except Exception:
            pass

    return info


def get_installed_software():
    """Read Munki's ApplicationInventory for installed software."""
    if not os.path.exists(APPLICATION_INVENTORY):
        return []

    try:
        with open(APPLICATION_INVENTORY, "rb") as f:
            inventory = plistlib.load(f)
        return [
            {
                "name": app.get("CFBundleName", app.get("name", "")),
                "version": app.get("CFBundleShortVersionString", ""),
                "bundle_id": app.get("bundleid", ""),
                "path": app.get("path", ""),
            }
            for app in inventory
        ]
    except Exception:
        return []


def get_install_results():
    """Parse Munki's ManagedInstallReport for install results."""
    if not os.path.exists(MUNKI_REPORT):
        return []

    try:
        with open(MUNKI_REPORT, "rb") as f:
            report = plistlib.load(f)

        results = []
        for item in report.get("InstallResults", []):
            results.append(
                {
                    "item_name": item.get("name", ""),
                    "item_version": item.get("version", ""),
                    "status": "installed" if item.get("status") == 0 else "failed",
                    "install_date": item.get("time", datetime.now()).isoformat()
                    if isinstance(item.get("time"), datetime)
                    else str(item.get("time", "")),
                }
            )

        for item in report.get("RemovalResults", []):
            results.append(
                {
                    "item_name": item.get("name", ""),
                    "item_version": item.get("version", ""),
                    "status": "removed"
                    if item.get("status") == 0
                    else "removal_failed",
                }
            )

        for item in report.get("ProblemInstalls", []):
            results.append(
                {
                    "item_name": item.get("name", ""),
                    "item_version": item.get("version", ""),
                    "status": "failed",
                    "error_message": item.get("note", ""),
                }
            )

        return results
    except Exception:
        return []


def checkin(config):
    """Perform a full check-in to the AutoMunki API."""
    serial = get_serial_number()
    hardware = get_hardware_info()
    munki = get_munki_info()
    software = get_installed_software()
    install_results = get_install_results()

    payload = {
        "serial_number": serial,
        "hostname": hardware.get("hostname"),
        "os_version": hardware.get("os_version"),
        "machine_model": hardware.get("machine_model"),
        "cpu_type": hardware.get("cpu_type"),
        "ram_mb": hardware.get("ram_mb"),
        "disk_size_gb": hardware.get("disk_size_gb"),
        "disk_free_gb": hardware.get("disk_free_gb"),
        "munki_version": munki.get("munki_version"),
        "manifest_name": munki.get("manifest_name"),
        "client_identifier": munki.get("client_identifier"),
        "installed_software": software,
        "install_results": install_results,
        "hardware_info": hardware,
    }

    try:
        url = f"{config['api_url']}/api/v1/reports/checkin"
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            print(f"Check-in successful for {serial}")
        else:
            print(f"Check-in failed: {response.status_code} {response.text}")
    except Exception as exc:
        print(f"Check-in error: {exc}")


def main():
    config = load_config()
    checkin(config)


if __name__ == "__main__":
    main()
