"""Optional default-password check for device admin panels.

**This is the one feature that actively authenticates.** It is off by default
and gated behind its own explicit consent (see :mod:`iotpwned.cli`). It exists to
answer a concrete, high-value question for someone auditing *their own* network:
*is my router/camera admin page still on its factory-default password?*

Design constraints (the "conservative & targeted" option):

* **HTTP Basic auth only.** We test credentials by sending one authenticated
  ``GET`` (an ``Authorization: Basic`` header) and checking whether it's accepted.
  This is deterministic and non-destructive — we never POST or change a setting.
  Form-based logins vary too much to test safely, so we skip them and say so.
* **Targeted.** Only likely admin devices are probed (the gateway, fingerprinted
  routers/cameras, hosts already exposing an admin port).
* **Small and polite.** A handful of well-known default pairs per device, a short
  delay between attempts, and we stop on the first success or a lockout signal.

The default-credential list is a small, curated set of *publicly documented*
manufacturer defaults (the same facts sites like portforward.com's router-password
list compile) — not a brute-force wordlist.
"""

from __future__ import annotations

import base64
import ssl
import time
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

from . import __version__
from .models import Finding, Host, Severity

# Admin ports we probe directly (the port scan doesn't cover 80/443).
ADMIN_PROBE_PORTS = [80, 443, 8080, 8443, 81]

# Well-known defaults tried on every candidate.
UNIVERSAL_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("", ""),
]

# Publicly documented per-brand factory defaults (keyed by fingerprint keyword).
BRAND_CREDS = {
    "hikvision": [("admin", "12345")],
    "dahua": [("admin", "admin"), ("888888", "888888")],
    "tp-link": [("admin", "admin")],
    "netgear": [("admin", "password")],
    "d-link": [("admin", ""), ("admin", "admin")],
    "dlink": [("admin", ""), ("admin", "admin")],
    "linksys": [("admin", "admin"), ("", "admin")],
    "asus": [("admin", "admin")],
    "zyxel": [("admin", "1234")],
    "tenda": [("admin", "admin")],
    "belkin": [("admin", "")],
    "netis": [("guest", "guest")],
    "axis": [("root", "pass")],
    "reolink": [("admin", "")],
}

_UA = {"User-Agent": f"IoTpwned/{__version__} (+local default-credential check)"}
_MAX_PAIRS = 8


def build_cred_list(host: Host) -> List[Tuple[str, str]]:
    """Default (user, pass) pairs to try for ``host`` — brand-specific first."""
    hay = f"{host.vendor or ''} {host.device_type or ''}".lower()
    pairs: List[Tuple[str, str]] = []
    for keyword, creds in BRAND_CREDS.items():
        if keyword in hay:
            pairs.extend(creds)
    for pair in UNIVERSAL_CREDS:
        if pair not in pairs:
            pairs.append(pair)
    return pairs[:_MAX_PAIRS]


def is_candidate(host: Host) -> bool:
    """Only probe likely admin devices, to keep the check targeted."""
    if host.is_gateway:
        return True
    dt = (host.device_type or "").lower()
    if any(k in dt for k in ("router", "gateway", "camera", "dvr", "nvr",
                             "admin panel", "nas")):
        return True
    return any(op.port in ADMIN_PROBE_PORTS for op in host.open_ports)


def _request(url: str, timeout: float, auth: Optional[Tuple[str, str]] = None):
    """Return (status_code, headers) or (None, None). GET only; never mutates."""
    req = urllib.request.Request(url, headers=dict(_UA))
    if auth is not None:
        raw = f"{auth[0]}:{auth[1]}".encode("latin-1", errors="replace")
        req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
    ctx = ssl._create_unverified_context() if url.startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers
    except (urllib.error.URLError, OSError, ValueError):
        return None, None


def basic_auth_realm(url: str, timeout: float) -> Optional[bool]:
    """True if ``url`` is protected by HTTP Basic auth, False if not, None if down."""
    status, headers = _request(url, timeout)
    if status is None:
        return None
    if status == 401 and headers is not None:
        return "basic" in (headers.get("WWW-Authenticate", "") or "").lower()
    return False


def try_default_creds(
    url: str,
    pairs: List[Tuple[str, str]],
    timeout: float,
    delay: float = 0.3,
):
    """Try each default pair against a Basic-auth ``url``.

    Returns the first working ``(user, pass)``, or None. Bails (returns None) on
    a lockout/rate-limit signal so we don't hammer the device.
    """
    for i, pair in enumerate(pairs):
        if i:
            time.sleep(delay)
        status, _ = _request(url, timeout, auth=pair)
        if status is None:
            return None
        if status in (429, 403):  # rate-limited / locked out -> stop
            return None
        if status < 400:          # accepted
            return pair
    return None


def check_host_credentials(
    host: Host,
    timeout: float = 5.0,
) -> Tuple[List[Finding], bool]:
    """Probe ``host``'s admin panels for default passwords.

    Returns ``(findings, tested)`` — ``tested`` is True if we found and probed a
    Basic-auth panel at all (so the caller can report coverage honestly).
    """
    if not is_candidate(host):
        return [], False

    pairs = build_cred_list(host)
    tested = False
    for port in ADMIN_PROBE_PORTS:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host.ip}:{port}/"
        realm = basic_auth_realm(url, timeout)
        if realm is None:
            continue          # nothing answering here
        if realm is False:
            continue          # not Basic auth (form login / open) -> skip safely
        tested = True
        working = try_default_creds(url, pairs, timeout)
        if working:
            user, pw = working
            u = user or "(blank)"
            p = pw or "(blank)"
            return (
                [Finding(
                    rule_id=f"weak-cred-{port}",
                    title=f"Admin panel accepts a default password ({u} / {p})",
                    severity=Severity.CRITICAL,
                    why=(
                        "This device's admin page still uses a factory-default "
                        "login. Anyone who can reach it can log straight in and "
                        "take full control — change settings, watch camera feeds, "
                        "or use it as a foothold into the rest of your network."
                    ),
                    fix=(
                        "Log in and set a strong, unique admin password now. If "
                        "it's your main router, also turn off remote (internet-"
                        "side) administration."
                    ),
                    port=port,
                    evidence=f"HTTP Basic auth on port {port} accepted {u}:{p}",
                )],
                tested,
            )
    return [], tested
