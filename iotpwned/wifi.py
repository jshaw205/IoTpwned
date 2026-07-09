"""Local Wi-Fi configuration check.

Reads the machine's *current* Wi-Fi connection from the OS and flags weak
encryption (Open / WEP / old WPA). This is a purely local read — no packets are
sent and nothing leaves the machine — so it runs by default.

Platform support:

* **Windows** — ``netsh wlan show interfaces``
* **macOS**   — the ``airport -I`` framework tool
* **Linux**   — ``nmcli`` (NetworkManager)

Parsing is split into pure functions (``parse_netsh_interfaces`` etc.) so they
can be unit-tested against captured output with no OS calls.

A note on WPS: whether a router has WPS enabled is an access-point property that
the client OS does not reliably expose, so IoTpwned does not claim to detect it.
The report instead gives a short advisory to disable WPS on the router.
"""

from __future__ import annotations

import platform
import subprocess
from typing import List, Optional, Tuple

from .models import Finding, Severity, WifiInfo

_SYSTEM = platform.system().lower()
_MACOS_AIRPORT = (
    "/System/Library/PrivateFrameworks/Apple80211.framework/"
    "Versions/Current/Resources/airport"
)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_auth(authentication: Optional[str], cipher: Optional[str]) -> str:
    """Normalise an OS auth/cipher string into a security category."""
    a = (authentication or "").lower()
    c = (cipher or "").lower()

    if "wpa3" in a or "sae" in a:
        return "wpa3"
    if "wpa2" in a or "rsn" in a:
        if "enterprise" in a or "802.1x" in a or "eap" in a:
            return "wpa2-enterprise"
        return "wpa2"
    if "wpa" in a:
        return "wpa"
    if "wep" in a or "wep" in c:
        return "wep"
    if a in ("open", "none", "") and "wep" not in c:
        # "Open" with a real cipher name shouldn't happen, but be safe.
        if c in ("", "none"):
            return "open"
    return "unknown"


# ---------------------------------------------------------------------------
# Parsers (pure)
# ---------------------------------------------------------------------------

def _split_kv(line: str) -> Optional[Tuple[str, str]]:
    if ":" not in line:
        return None
    key, _, value = line.partition(":")
    return key.strip(), value.strip()


def parse_netsh_interfaces(text: str) -> WifiInfo:
    """Parse Windows ``netsh wlan show interfaces`` output."""
    # Split into per-interface blocks (each starts with a "Name" line).
    blocks: List[dict] = []
    current: Optional[dict] = None
    for line in text.splitlines():
        kv = _split_kv(line)
        if not kv:
            continue
        key, value = kv
        if key.lower() == "name":
            current = {}
            blocks.append(current)
        if current is not None:
            current[key.lower()] = value

    if not blocks:
        return WifiInfo(supported=True, connected=False, platform="windows")

    # Prefer a connected interface; otherwise the first one.
    block = next(
        (b for b in blocks if b.get("state", "").lower() == "connected"),
        blocks[0],
    )
    connected = block.get("state", "").lower() == "connected"
    if not connected:
        return WifiInfo(supported=True, connected=False, platform="windows")

    auth = block.get("authentication")
    cipher = block.get("cipher")
    return WifiInfo(
        supported=True,
        connected=True,
        ssid=block.get("ssid") or None,
        authentication=auth,
        cipher=cipher,
        category=classify_auth(auth, cipher),
        band=block.get("band"),
        platform="windows",
    )


def parse_airport(text: str) -> WifiInfo:
    """Parse macOS ``airport -I`` output (``key: value`` per line)."""
    fields = {}
    for line in text.splitlines():
        kv = _split_kv(line)
        if kv:
            fields[kv[0].lower()] = kv[1]

    if not fields or fields.get("state", "").lower() in ("init", ""):
        return WifiInfo(supported=True, connected=False, platform="macos")

    auth = fields.get("link auth")
    ssid = fields.get("ssid")
    if not ssid and not auth:
        return WifiInfo(supported=True, connected=False, platform="macos")
    return WifiInfo(
        supported=True,
        connected=True,
        ssid=ssid or None,
        authentication=auth,
        cipher=None,
        category=classify_auth(auth, None),
        platform="macos",
    )


def parse_nmcli(text: str) -> WifiInfo:
    """Parse Linux ``nmcli -t -f IN-USE,SSID,SECURITY dev wifi`` output.

    The active network's row starts with ``*``. Fields are ``:``-separated;
    nmcli escapes literal colons as ``\\:``.
    """
    for raw in text.splitlines():
        if not raw.startswith("*"):
            continue
        # Unescape nmcli's "\:" then split on unescaped colons.
        parts = raw.replace("\\:", "\x00").split(":")
        parts = [p.replace("\x00", ":") for p in parts]
        in_use = parts[0].strip() if len(parts) > 0 else ""
        ssid = parts[1].strip() if len(parts) > 1 else ""
        security = parts[2].strip() if len(parts) > 2 else ""
        if in_use != "*":
            continue
        category = classify_auth(security, None)
        if security in ("", "--"):
            category = "open"
        return WifiInfo(
            supported=True,
            connected=True,
            ssid=ssid or None,
            authentication=security or "Open",
            cipher=None,
            category=category,
            platform="linux",
        )
    return WifiInfo(supported=True, connected=False, platform="linux")


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def _run(cmd: List[str]) -> Optional[str]:
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 and not proc.stdout:
        return None
    return proc.stdout


def get_wifi_info() -> WifiInfo:
    """Detect the current Wi-Fi connection for this platform."""
    if _SYSTEM.startswith("win"):
        out = _run(["netsh", "wlan", "show", "interfaces"])
        if out is None:
            return WifiInfo(supported=False, platform="windows")
        return parse_netsh_interfaces(out)

    if _SYSTEM == "darwin":
        out = _run([_MACOS_AIRPORT, "-I"])
        if out is None:
            return WifiInfo(supported=False, platform="macos")
        return parse_airport(out)

    if _SYSTEM == "linux":
        out = _run(["nmcli", "-t", "-f", "IN-USE,SSID,SECURITY", "dev", "wifi"])
        if out is None:
            return WifiInfo(supported=False, platform="linux")
        return parse_nmcli(out)

    return WifiInfo(supported=False, platform=_SYSTEM)


# ---------------------------------------------------------------------------
# Risk evaluation
# ---------------------------------------------------------------------------

_WIFI_RULES = {
    "open": (
        Severity.CRITICAL,
        "Your Wi-Fi is open (no password or encryption)",
        "Anyone within range can join your network and read the traffic of every "
        "device on it — including cameras and smart-home gear.",
        "Set a WPA2 or WPA3 password on your router right away.",
    ),
    "wep": (
        Severity.CRITICAL,
        "Your Wi-Fi uses WEP encryption",
        "WEP is thoroughly broken and can be cracked in minutes with free tools, "
        "giving an attacker full access to your network.",
        "Switch your router's security to WPA2 or (better) WPA3 immediately.",
    ),
    "wpa": (
        Severity.HIGH,
        "Your Wi-Fi uses the outdated WPA (TKIP) encryption",
        "The original WPA/TKIP is deprecated and practically crackable. It's a "
        "weak lock on the front door of your whole network.",
        "Change your router's security mode to WPA2 or WPA3.",
    ),
}


def evaluate_wifi(info: WifiInfo) -> List[Finding]:
    """Return findings for a Wi-Fi connection (only for real problems)."""
    if not info.supported or not info.connected:
        return []

    rule = _WIFI_RULES.get(info.category)
    if rule is None:
        return []  # wpa2 / wpa2-enterprise / wpa3 / unknown -> no problem finding

    severity, title, why, fix = rule
    where = f" ({info.ssid})" if info.ssid else ""
    return [
        Finding(
            rule_id=f"wifi-{info.category}",
            title=title + where,
            severity=severity,
            why=why,
            fix=fix,
            evidence=f"Wi-Fi authentication: {info.authentication or 'unknown'}",
        )
    ]


def check_wifi() -> Tuple[WifiInfo, List[Finding]]:
    """Convenience: detect Wi-Fi and evaluate it in one call."""
    info = get_wifi_info()
    return info, evaluate_wifi(info)
