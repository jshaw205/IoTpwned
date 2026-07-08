"""A local, offline snapshot of well-known CVEs for common home IoT/router gear.

This is deliberately a *curated* snapshot, not a full CVE feed — enough to flag
the notorious, widely-exploited flaws in the device families IoTpwned already
fingerprints. Everything stays on the machine (privacy-first): no NVD API calls.

Matching is heuristic. We can see a device's brand/family from its banner and
MAC vendor, but not its exact firmware version, so a match means *"this device
family had this flaw — make sure your firmware is patched,"* not a confirmed
exploit. The finding text says so.

**Extending coverage** (roadmap: "match fingerprinted banners against a local
snapshot of known CVEs"): add a :class:`CVERecord` below. ``match_any`` is a list
of lowercase substrings — a record matches if ANY appears in the haystack built
from the device's vendor + device type + grabbed banners. Use ``require_all`` to
narrow a match (every substring must be present).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from .models import Severity


@dataclass(frozen=True)
class CVERecord:
    cve_id: str
    product: str                 # human-readable affected product/family
    match_any: Tuple[str, ...]   # matches if ANY of these appear (lowercase)
    severity: Severity
    summary: str                 # plain-English: what the flaw is
    fix: str                     # what the user should do
    reference: str = ""          # advisory URL (shown in console/JSON, not HTML)
    require_all: Tuple[str, ...] = ()  # optional: ALL must also appear


# NOTE: severities reflect the real-world seriousness of each flaw. Because our
# detection is family-level (not firmware-exact), the finding wording frames each
# as "verify your firmware is patched."
CVE_SNAPSHOT: List[CVERecord] = [
    CVERecord(
        "CVE-2021-36260", "Hikvision cameras & NVRs",
        ("hikvision",), Severity.CRITICAL,
        "A command-injection bug in the web interface of many Hikvision cameras "
        "and recorders lets an attacker take full control of the device without "
        "logging in. It has been widely scanned for and exploited.",
        "Update the device firmware to the latest version from Hikvision. If it "
        "can't be updated, keep it off the internet and on an isolated network.",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-36260",
    ),
    CVERecord(
        "CVE-2017-7921", "Hikvision cameras",
        ("hikvision",), Severity.HIGH,
        "An authentication-bypass flaw in some Hikvision cameras lets attackers "
        "read device information and user credentials without a valid login.",
        "Update the camera firmware and change all passwords afterwards.",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-7921",
    ),
    CVERecord(
        "CVE-2021-33044", "Dahua cameras & NVRs",
        ("dahua",), Severity.CRITICAL,
        "An authentication-bypass flaw in several Dahua cameras and recorders "
        "lets an attacker log in without valid credentials by sending a crafted "
        "login request.",
        "Update the device firmware to a fixed version from Dahua and keep it off "
        "the public internet.",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-33044",
    ),
    CVERecord(
        "CVE-2017-7925", "Dahua cameras & DVRs",
        ("dahua",), Severity.HIGH,
        "Some Dahua devices store credentials insecurely, so an attacker who can "
        "reach the device may recover the admin password from its configuration.",
        "Update the firmware and change the admin password once patched.",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-7925",
    ),
    CVERecord(
        "CVE-2016-6277", "Netgear routers (R7000/R6400 family)",
        ("netgear",), Severity.CRITICAL,
        "A command-injection bug in several Netgear routers (such as the R7000 "
        "and R6400) allows remote takeover of the router.",
        "Update the router firmware from Netgear. If no update exists for your "
        "model, consider replacing it.",
        "https://nvd.nist.gov/vuln/detail/CVE-2016-6277",
    ),
    CVERecord(
        "CVE-2018-14847", "MikroTik RouterOS",
        ("mikrotik", "routeros"), Severity.HIGH,
        "A path-traversal bug in MikroTik RouterOS (via the Winbox service) lets "
        "attackers read files and extract admin credentials. It was used at scale "
        "to build botnets.",
        "Upgrade RouterOS to a current release and restrict Winbox access.",
        "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
    ),
    CVERecord(
        "CVE-2014-9222", "Routers using the RomPager web server",
        ("rompager",), Severity.CRITICAL,
        "The 'Misfortune Cookie' flaw in the RomPager web server built into many "
        "home routers lets an attacker take administrative control of the router.",
        "Update the router firmware. Many affected models are end-of-life — if no "
        "fix is available, replace the router.",
        "https://nvd.nist.gov/vuln/detail/CVE-2014-9222",
    ),
    CVERecord(
        "CVE-2017-8225", "Cameras using the GoAhead web server",
        ("goahead",), Severity.HIGH,
        "Many low-cost IP cameras built on the GoAhead web server allow "
        "unauthenticated access to snapshots and credentials.",
        "Update the camera firmware if a fix exists; otherwise isolate the camera "
        "on a separate network and never expose it to the internet.",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-8225",
    ),
    CVERecord(
        "CVE-2017-7577", "Xiongmai-based cameras/DVRs (uc-httpd)",
        ("uc-httpd", "xiongmai"), Severity.HIGH,
        "A path-traversal bug in the uc-httpd server used by Xiongmai-based "
        "cameras and DVRs (sold under many brands) exposes device files. This gear "
        "was central to the Mirai botnet.",
        "These devices are notoriously hard to secure. Update firmware if possible, "
        "and isolate or replace them.",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-7577",
    ),
    CVERecord(
        "CVE-2023-1389", "TP-Link Archer AX21",
        ("archer",), Severity.CRITICAL,
        "An unauthenticated command-injection bug in the TP-Link Archer AX21 "
        "router is being actively exploited by botnets (including Mirai variants).",
        "Update the router firmware from TP-Link to the latest version.",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-1389",
    ),
]
