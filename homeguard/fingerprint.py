"""Device fingerprinting — turn raw ports/banners/MACs into a device label.

Two signals are combined:

* **MAC vendor** — via the optional ``mac-vendor-lookup`` package (offline
  Wireshark OUI database) if installed, otherwise a small built-in table.
* **Banner signatures** — regexes matched against grabbed banners to spot
  camera/DVR/router brands and admin panels.

If neither reveals a brand we fall back to a category hint from the open ports
(e.g. "IP camera / DVR" when an RTSP port is open).
"""

from __future__ import annotations

import re
from typing import List, Optional

from .data import (
    BANNER_SIGNATURES,
    CATEGORY_DEVICE_HINT,
    OUI_FALLBACK,
    PORT_SPECS,
)
from .discovery import normalise_mac
from .models import Host

# Try the optional dependency once, at import time.
try:  # pragma: no cover - depends on optional install
    from mac_vendor_lookup import MacLookup

    _MAC_LOOKUP = MacLookup()
except Exception:  # pragma: no cover
    _MAC_LOOKUP = None

_COMPILED_SIGS = [(re.compile(pat, re.IGNORECASE), label) for pat, label in BANNER_SIGNATURES]


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """Return a best-effort hardware vendor for ``mac``.

    Prefers the offline ``mac-vendor-lookup`` database; falls back to
    HomeGuard's small built-in OUI table. Returns None if unknown.
    """
    if not mac:
        return None
    mac = normalise_mac(mac)

    if _MAC_LOOKUP is not None:
        try:
            return _MAC_LOOKUP.lookup(mac)
        except Exception:
            pass  # not found / offline db missing -> fall through

    prefix = mac[:8]  # "AA:BB:CC"
    return OUI_FALLBACK.get(prefix)


def label_from_banners(banners: List[str]) -> Optional[str]:
    """Return a device label from the first matching banner signature."""
    for banner in banners:
        if not banner:
            continue
        for pattern, label in _COMPILED_SIGS:
            if pattern.search(banner):
                return label
    return None


def label_from_ports(ports: List[int]) -> Optional[str]:
    """Guess a device class from the open ports' categories."""
    # Prefer the most specific category present (camera before generic panel).
    priority = [
        "camera",
        "router-mgmt",
        "iot-messaging",
        "file-sharing",
        "upnp",
        "admin-panel",
    ]
    present = set()
    for port in ports:
        spec = PORT_SPECS.get(port)
        if spec:
            present.add(spec.category)
    for cat in priority:
        if cat in present and cat in CATEGORY_DEVICE_HINT:
            return CATEGORY_DEVICE_HINT[cat]
    return None


def fingerprint_host(host: Host) -> Host:
    """Fill in ``host.vendor`` and ``host.device_type`` in place."""
    host.vendor = lookup_vendor(host.mac)

    banners = [op.banner for op in host.open_ports]
    open_port_numbers = [op.port for op in host.open_ports]

    device = label_from_banners(banners)
    if device is None:
        device = label_from_ports(open_port_numbers)

    if device is None:
        if host.is_gateway:
            device = "Router / gateway"
        elif host.vendor:
            device = f"{host.vendor} device"
        elif host.open_ports:
            device = "Unknown IoT device"
        else:
            device = "Unknown device"

    host.device_type = device
    return host


def fingerprint_hosts(hosts: List[Host]) -> List[Host]:
    for host in hosts:
        fingerprint_host(host)
    return hosts
