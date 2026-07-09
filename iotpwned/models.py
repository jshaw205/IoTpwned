"""Shared data models used across the IoTpwned pipeline.

Kept dependency-free (dataclasses + enum only) so every stage — discovery,
scanning, fingerprinting, risk scoring, reporting — can import these without
creating circular dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """Ordered risk severity. Higher value == more serious."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    def __lt__(self, other: "Severity") -> bool:  # enables sorting
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value


@dataclass
class OpenPort:
    """A TCP port found open on a host, with an optional grabbed banner."""

    port: int
    service: str = "unknown"
    banner: str = ""


@dataclass
class Host:
    """A single device discovered on the local network."""

    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    device_type: str = "Unknown device"
    open_ports: List[OpenPort] = field(default_factory=list)
    findings: List["Finding"] = field(default_factory=list)
    is_gateway: bool = False

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)


@dataclass
class Finding:
    """A single risk observation about a host, in plain English."""

    rule_id: str
    title: str
    severity: Severity
    why: str  # why this matters, jargon-free
    fix: str  # what the user should do about it
    port: Optional[int] = None
    evidence: str = ""
    reference: str = ""  # optional advisory URL (e.g. a CVE detail page)


@dataclass
class WifiInfo:
    """The local machine's current Wi-Fi connection, as read from the OS."""

    supported: bool = True   # False if we couldn't read Wi-Fi on this platform
    connected: bool = False
    ssid: Optional[str] = None
    authentication: Optional[str] = None  # raw string from the OS
    cipher: Optional[str] = None
    category: str = "unknown"  # open/wep/wpa/wpa2/wpa2-enterprise/wpa3/unknown
    band: Optional[str] = None
    platform: str = ""


@dataclass
class ScanResult:
    """The full result of one IoTpwned run."""

    subnet: str
    hosts: List[Host] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    grade: str = "?"
    score: int = 100
    meta: Dict[str, str] = field(default_factory=dict)
    # Findings about the network/machine itself rather than a specific host
    # (e.g. weak Wi-Fi encryption). These count toward the grade too.
    network_findings: List[Finding] = field(default_factory=list)
    wifi: Optional[WifiInfo] = None

    @property
    def all_findings(self) -> List[Finding]:
        out: List[Finding] = []
        for h in self.hosts:
            out.extend(h.findings)
        out.extend(self.network_findings)
        return out
