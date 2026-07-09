"""Optional external (internet-facing) exposure check.

The LAN scan can only see your network from the inside. This module checks it
from the *outside*: it finds your public IP and asks **Shodan's InternetDB**
what's reachable there from the open internet.

Like the online CVE lookup, this is the exception to IoTpwned's "nothing leaves
the machine" rule, so it is:

* **Opt-in and consent-gated** (see :mod:`iotpwned.cli`).
* **Minimal.** The only thing sent off-machine is your public IP address — first
  to a "what's my IP" echo service, then to Shodan's InternetDB. No LAN details,
  device names, MAC addresses, or banners.

**Honesty about the data:** InternetDB reflects Shodan's most recent internet-wide
scan, not a live probe. So an open port means it *was* reachable when Shodan last
looked; an empty result is not a guarantee that nothing is exposed.

Source: https://internetdb.shodan.io/ (free, no API key).
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

from . import __version__
from .data import PORT_SPECS
from .models import Finding, Severity, WanInfo

# Plain-text "what's my (IPv4) address" services, tried in order.
_IP_ECHO_SERVICES = [
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://ifconfig.me/ip",
]
_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

# Ports that are especially alarming when reachable from the internet
# (remote administration, cameras/DVRs, router management, backdoors).
_CRITICAL_WAN_PORTS = {
    21, 23, 2323, 139, 445, 3389, 5555, 5900, 7547, 37777, 34567, 32764,
}

_UA = {"User-Agent": f"IoTpwned/{__version__} (+local security scan)"}


def get_public_ip(timeout: float = 10.0) -> Optional[str]:
    """Return this network's public IPv4 address, or None if undeterminable."""
    for url in _IP_ECHO_SERVICES:
        try:
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="replace").strip()
            addr = ipaddress.ip_address(text)
            if isinstance(addr, ipaddress.IPv4Address):
                return str(addr)
        except (urllib.error.URLError, ValueError, OSError):
            continue
    return None


def query_internetdb(ip: str, timeout: float = 15.0):
    """Query Shodan InternetDB for ``ip``.

    Returns the parsed dict on success, ``{}`` when Shodan has no record (a 404,
    which is the "nothing known exposed" case), or ``None`` on any error.
    """
    req = urllib.request.Request(_INTERNETDB_URL.format(ip=ip), headers=_UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        return None
    except (urllib.error.URLError, ValueError, OSError):
        return None


def mask_ip(ip: Optional[str]) -> Optional[str]:
    """Mask the host portion of an IPv4 address for shareable output."""
    if not ip:
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip


def evaluate_wan(info: WanInfo) -> List[Finding]:
    """Turn an exposure result into findings (only for real exposure)."""
    if not info.checked or not info.public_ip:
        return []

    findings: List[Finding] = []
    for port in sorted(set(info.open_ports))[:12]:
        spec = PORT_SPECS.get(port)
        service = spec.service if spec else "a service"
        severity = (Severity.CRITICAL if port in _CRITICAL_WAN_PORTS
                    else Severity.HIGH)
        findings.append(
            Finding(
                rule_id=f"wan-port-{port}",
                title=f"Port {port} ({service}) is reachable from the internet",
                severity=severity,
                why=(
                    "This port on your public IP was reachable from the open "
                    "internet when Shodan last scanned it — anyone in the world "
                    "can try to connect to it, not just devices on your home "
                    "network. Exposed services like this are constantly probed "
                    "and attacked."
                ),
                fix=(
                    "On your router, remove the port-forward for this port and "
                    "turn off UPnP if you don't rely on it. Only forward ports "
                    "you deliberately expose, and put a strong password on "
                    "whatever answers them."
                ),
                evidence=f"Shodan InternetDB: TCP {port} open on your public IP",
            )
        )

    if info.vulns:
        shown = ", ".join(sorted(info.vulns)[:8])
        more = "" if len(info.vulns) <= 8 else f" (+{len(info.vulns) - 8} more)"
        count = len(info.vulns)
        findings.append(
            Finding(
                rule_id="wan-known-vulns",
                title=(f"Shodan reports {count} known vulnerabilit"
                       f"{'y' if count == 1 else 'ies'} on your public IP"),
                severity=Severity.CRITICAL,
                why=(
                    "Shodan associates known CVEs with a service exposed on your "
                    "public-facing IP. Internet-facing devices with known bugs "
                    "are exactly what automated attacks and botnets hunt for."
                ),
                fix=(
                    "Update the firmware of whatever device is exposed, and stop "
                    "exposing it to the internet if at all possible."
                ),
                evidence=f"CVEs: {shown}{more}",
            )
        )

    return findings


def check_wan(
    public_ip: Optional[str] = None,
    timeout: float = 15.0,
) -> Tuple[WanInfo, List[Finding]]:
    """Determine the public IP (unless given) and check external exposure."""
    ip = public_ip or get_public_ip(timeout=timeout)
    if not ip:
        return (
            WanInfo(checked=False, supported=False,
                    error="Could not determine your public IP address."),
            [],
        )

    data = query_internetdb(ip, timeout=timeout)
    if data is None:
        return (
            WanInfo(checked=False, supported=True, public_ip=ip,
                    error="Could not reach Shodan InternetDB."),
            [],
        )

    info = WanInfo(
        checked=True,
        supported=True,
        public_ip=ip,
        open_ports=sorted({int(p) for p in data.get("ports", [])}),
        vulns=list(data.get("vulns", [])),
        hostnames=list(data.get("hostnames", [])),
    )
    return info, evaluate_wan(info)
