"""Apple Find My–style device thumbnails (same CDN as MunkiReport).

MunkiReport resolves icons via ``get_model_icon`` using iCloud static URLs; see
https://github.com/munkireport/machine/blob/master/machine_controller.php
"""

from __future__ import annotations

from urllib.parse import quote


def derive_apple_image_family(product_name: str | None, machine_model: str | None) -> str:
    """First path segment for FMIP deviceImages (spaces removed from marketing name, or model-id prefix)."""
    mm = (machine_model or "").strip()
    if mm == "iMacPro1,1":
        return "iMac"
    if product_name:
        compact = "".join(str(product_name).split())
        if compact:
            return compact
    for i, c in enumerate(mm):
        if c.isdigit():
            return mm[:i] or mm
    return mm


def apple_fmip_device_image_url(
    serial_number: str,
    machine_model: str | None,
    hardware_info: dict | None,
) -> str | None:
    """Return a PNG URL, or None if we cannot build one."""
    if not serial_number or not serial_number.strip():
        return None

    hw = hardware_info if isinstance(hardware_info, dict) else {}
    mm = (machine_model or "").strip()
    if not mm:
        raw = hw.get("machine_model")
        if isinstance(raw, str) and raw.strip():
            mm = raw.strip()
            machine_model = mm

    sn = serial_number.strip()
    # MunkiReport: mixed-case serial → VM / non-hardware; use support image servlet.
    if sn != sn.upper():
        return f"https://km.support.apple.com/kb/securedImage.jsp?productid={quote(sn)}&size=240x240"

    raw_family = hw.get("apple_image_family")
    if isinstance(raw_family, str) and raw_family.strip():
        family = raw_family.strip()
    else:
        pn = hw.get("product_name") if isinstance(hw.get("product_name"), str) else None
        family = derive_apple_image_family(pn, machine_model)

    mm = (machine_model or "").strip()
    if not family or not mm:
        return None

    if mm == "iMacPro1,1":
        family = "iMac"

    base = "https://statici.icloud.com/fmipmobile/deviceImages-9.0"
    return f"{base}/{quote(family, safe='')}/{quote(mm, safe='')}/online-infobox__2x.png"
