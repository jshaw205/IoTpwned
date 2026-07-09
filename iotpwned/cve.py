"""Match fingerprinted devices against the local CVE snapshot.

Given a fingerprinted :class:`Host` (vendor, device type, banners already set),
we build a lowercase "haystack" and check each :class:`CVERecord`. Matches become
:class:`Finding` objects that flow through the normal risk report.

Because detection is family-level rather than firmware-exact, every CVE finding
is framed as *"verify your firmware is patched."*
"""

from __future__ import annotations

from typing import List

from .cve_data import CVE_SNAPSHOT, CVERecord
from .models import Finding, Host


def _haystack(host: Host) -> str:
    """Combine the signals we fingerprint from into one lowercase string."""
    parts: List[str] = []
    if host.vendor:
        parts.append(host.vendor)
    if host.device_type:
        parts.append(host.device_type)
    for op in host.open_ports:
        if op.banner:
            parts.append(op.banner)
    return " ".join(parts).lower()


def _matches(record: CVERecord, haystack: str) -> bool:
    if not any(token in haystack for token in record.match_any):
        return False
    if record.require_all and not all(t in haystack for t in record.require_all):
        return False
    return True


def match_cves(host: Host) -> List[CVERecord]:
    """Return the CVE records whose device family matches ``host``."""
    haystack = _haystack(host)
    if not haystack.strip():
        return []
    return [rec for rec in CVE_SNAPSHOT if _matches(rec, haystack)]


def cve_findings(host: Host) -> List[Finding]:
    """Turn matched CVEs into plain-English :class:`Finding` objects."""
    findings: List[Finding] = []
    for rec in match_cves(host):
        why = (
            f"{rec.summary} This was flagged because the device matches the "
            f"{rec.product} family. Confirm your firmware is up to date; a fully "
            f"patched device isn't affected."
        )
        findings.append(
            Finding(
                rule_id=f"cve-{rec.cve_id}",
                title=f"Known vulnerability {rec.cve_id} ({rec.product})",
                severity=rec.severity,
                why=why,
                fix=rec.fix,
                evidence=f"matched device family: {rec.product}",
                reference=rec.reference,
            )
        )
    return findings
