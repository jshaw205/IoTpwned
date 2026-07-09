"""Optional ONLINE CVE lookup against the NIST NVD API.

This is the one place IoTpwned can talk to the internet, so it is deliberately
constrained:

* **Opt-in only.** Nothing here runs unless the user passes ``--online-cve`` and
  explicitly consents at runtime (see :func:`iotpwned.cli`).
* **Data minimisation.** The only thing sent off-machine is a device *brand
  keyword* we already recognised (e.g. ``"Hikvision"``). No IP addresses, MAC
  addresses, hostnames, or raw banners are ever transmitted. The consent prompt
  shows the exact keywords first.
* **Graceful offline behaviour.** Any network/parse error is swallowed per
  keyword; the offline snapshot results still stand.

Source: NVD 2.0 REST API (https://services.nvd.nist.gov/rest/json/cves/2.0).
Free and needs no API key; set ``NVD_API_KEY`` for a higher rate limit.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from . import __version__
from .models import Finding, Host, Severity

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Brand tokens we might see in a fingerprint -> the keyword we search NVD for.
# Only recognised brands are ever queried, which bounds what leaves the machine.
BRAND_KEYWORDS: Dict[str, str] = {
    "hikvision": "Hikvision",
    "dahua": "Dahua",
    "netgear": "Netgear",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "archer": "TP-Link",
    "asus": "ASUS",
    "mikrotik": "MikroTik",
    "routeros": "MikroTik",
    "ubiquiti": "Ubiquiti",
    "unifi": "Ubiquiti",
    "synology": "Synology",
    "qnap": "QNAP",
    "axis": "Axis",
    "reolink": "Reolink",
    "wyze": "Wyze",
    "roku": "Roku",
    "sonos": "Sonos",
    "d-link": "D-Link",
    "dlink": "D-Link",
    "zyxel": "Zyxel",
    "tenda": "Tenda",
    "foscam": "Foscam",
}

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass
class OnlineCVE:
    cve_id: str
    score: Optional[float]
    severity: Severity
    description: str
    url: str


def _host_haystack(host: Host) -> str:
    parts = [host.vendor or "", host.device_type or ""]
    return " ".join(parts).lower()


def derive_keywords(hosts: List[Host]) -> Dict[str, List[Host]]:
    """Map each recognised brand keyword to the hosts it was found on.

    Returns an ordered ``{keyword: [hosts]}`` dict. Only brands in
    :data:`BRAND_KEYWORDS` are included, so unknown/generic devices contribute
    nothing to what would be sent to the API.
    """
    mapping: Dict[str, List[Host]] = {}
    for host in hosts:
        hay = _host_haystack(host)
        matched: Set[str] = set()
        for token, keyword in BRAND_KEYWORDS.items():
            if token in hay:
                matched.add(keyword)
        for keyword in matched:
            mapping.setdefault(keyword, []).append(host)
    return mapping


def _severity_from(score: Optional[float], label: str) -> Severity:
    label = (label or "").upper()
    if label in ("CRITICAL",):
        return Severity.CRITICAL
    if label in ("HIGH",):
        return Severity.HIGH
    if label in ("MEDIUM",):
        return Severity.MEDIUM
    if label in ("LOW",):
        return Severity.LOW
    # Fall back to the numeric CVSS base score.
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _extract_metric(cve: dict):
    """Return (score, severity_label) preferring CVSS v3.1 > v3.0 > v2."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity", "")
    entries = metrics.get("cvssMetricV2")
    if entries:
        data = entries[0].get("cvssData", {})
        # v2 has no baseSeverity in cvssData; use the entry-level one if present.
        return data.get("baseScore"), entries[0].get("baseSeverity", "")
    return None, ""


def parse_nvd_response(payload: dict, limit: int) -> List[OnlineCVE]:
    """Parse an NVD 2.0 JSON payload into up to ``limit`` OnlineCVEs.

    Pure function (no network) so it can be unit-tested with captured data.
    Results are sorted most-severe first (by CVSS base score).
    """
    out: List[OnlineCVE] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        score, label = _extract_metric(cve)
        out.append(
            OnlineCVE(
                cve_id=cve_id,
                score=score,
                severity=_severity_from(score, label),
                description=description,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )

    out.sort(key=lambda c: (c.score if c.score is not None else -1.0), reverse=True)
    return out[:limit]


def query_nvd(
    keyword: str,
    limit: int = 5,
    timeout: float = 15.0,
    api_key: Optional[str] = None,
    page_size: int = 40,
) -> List[OnlineCVE]:
    """Query the NVD API for ``keyword`` and return up to ``limit`` OnlineCVEs.

    Returns [] on any network or parse error (caller keeps offline results).
    """
    params = urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": page_size}
    )
    req = urllib.request.Request(f"{NVD_ENDPOINT}?{params}")
    req.add_header("User-Agent", f"IoTpwned/{__version__} (+local security scan)")
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            ValueError, OSError):
        return []

    return parse_nvd_response(payload, limit)


def _existing_cve_ids(host: Host) -> Set[str]:
    ids: Set[str] = set()
    for f in host.findings:
        m = _CVE_ID_RE.search(f.rule_id or "")
        if m:
            ids.add(m.group(0).upper())
    return ids


def _finding_from(cve: OnlineCVE, keyword: str) -> Finding:
    desc = cve.description.strip()
    if len(desc) > 240:
        desc = desc[:237].rstrip() + "..."
    why = (
        f"{desc} Reported by the live NIST NVD database for '{keyword}' devices. "
        f"Confirm your firmware is up to date; a fully patched device may not be "
        f"affected."
    )
    score_txt = f", CVSS {cve.score}" if cve.score is not None else ""
    return Finding(
        rule_id=f"cve-online-{cve.cve_id}",
        title=f"Known vulnerability {cve.cve_id} ({keyword})",
        severity=cve.severity,
        why=why,
        fix=(
            "Check the device maker's site for a firmware update that addresses "
            "this CVE, and keep the device off the public internet."
        ),
        evidence=f"NVD live lookup: {keyword}{score_txt}",
        reference=cve.url,
    )


def enrich(
    keyword_map: Dict[str, List[Host]],
    limit: int = 5,
    timeout: float = 15.0,
    api_key: Optional[str] = None,
    delay: Optional[float] = None,
    progress=None,
) -> int:
    """Query NVD for each keyword and attach findings to matching hosts.

    Skips CVEs already present on a host (e.g. from the offline snapshot).
    Returns the number of new findings added. Honours a polite inter-request
    delay to respect NVD rate limits (shorter when an API key is set).
    """
    if delay is None:
        delay = 0.8 if api_key else 6.5

    added = 0
    keywords = list(keyword_map.keys())
    for idx, keyword in enumerate(keywords):
        if idx > 0:
            time.sleep(delay)  # rate-limit courtesy between calls
        if progress:
            progress(idx + 1, len(keywords), keyword)

        cves = query_nvd(keyword, limit=limit, timeout=timeout, api_key=api_key)
        for host in keyword_map[keyword]:
            existing = _existing_cve_ids(host)
            for cve in cves:
                if cve.cve_id.upper() in existing:
                    continue
                host.findings.append(_finding_from(cve, keyword))
                existing.add(cve.cve_id.upper())
                added += 1

    # Keep each host's findings sorted most-severe first for the report.
    for hosts in keyword_map.values():
        for host in hosts:
            host.findings.sort(key=lambda f: (-f.severity.value, f.port or 0))

    return added
