"""The risk engine — turn open ports and banners into scored, plain-English findings.

Rules are deliberately simple and transparent (no ML, no black box):

* Every open risky port produces a :class:`Finding` from its :class:`PortSpec`.
* Some cross-cutting rules add findings (e.g. a default-cred-prone admin panel,
  a device exposing an unusually large attack surface).
* Findings are scored into a 0–100 network health number and an A–F grade.

Note (ethics): the risk engine only *flags* that a default-credential-prone
service is open — it never logs in. Actually testing default passwords is a
separate, opt-in, consent-gated feature (see ``credcheck.py``).
"""

from __future__ import annotations

from typing import List

from .cve import cve_findings
from .data import PORT_SPECS
from .models import Finding, Host, ScanResult, Severity

# Points deducted from a starting score of 100 per finding, by severity.
_SEVERITY_PENALTY = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 18,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def evaluate_host(host: Host) -> List[Finding]:
    """Produce the list of findings for a single host (also stored on it)."""
    findings: List[Finding] = []

    for op in host.open_ports:
        spec = PORT_SPECS.get(op.port)
        if spec is None:
            continue
        evidence = f"TCP {op.port} open"
        if op.banner:
            evidence += f" — banner: {op.banner[:120]}"
        findings.append(
            Finding(
                rule_id=f"port-{op.port}",
                title=f"{spec.service} exposed (port {op.port})",
                severity=spec.severity,
                why=spec.why,
                fix=spec.fix,
                port=op.port,
                evidence=evidence,
            )
        )

    findings.extend(_cross_cutting_rules(host))

    # Known-CVE matches against the fingerprinted device family.
    findings.extend(cve_findings(host))

    # Most serious first, then by port for stable ordering.
    findings.sort(key=lambda f: (-f.severity.value, f.port or 0))
    host.findings = findings
    return findings


def _cross_cutting_rules(host: Host) -> List[Finding]:
    out: List[Finding] = []
    open_ports = {op.port for op in host.open_ports}

    # Rule: several default-credential-prone services on one device.
    cred_prone = [
        p for p in open_ports
        if (spec := PORT_SPECS.get(p)) and spec.default_cred_prone
    ]
    if len(cred_prone) >= 2:
        out.append(
            Finding(
                rule_id="many-default-cred-services",
                title="Multiple login-exposed services on one device",
                severity=Severity.HIGH,
                why=(
                    "This device exposes several services that are commonly "
                    "left on factory-default passwords. Together they give an "
                    "attacker multiple ways in, and IoT gear like this is "
                    "exactly what botnets scan for."
                ),
                fix=(
                    "Change every default password on this device, turn off any "
                    "remote-access service you don't use, and check the maker's "
                    "site for a firmware update."
                ),
                evidence="Ports: " + ", ".join(str(p) for p in sorted(cred_prone)),
            )
        )

    # Rule: large overall attack surface.
    if len(open_ports) >= 6:
        out.append(
            Finding(
                rule_id="large-attack-surface",
                title="Unusually large number of open ports",
                severity=Severity.MEDIUM,
                why=(
                    "This device is listening on a lot of network ports. Every "
                    "open port is a potential way in — most home devices should "
                    "expose only one or two."
                ),
                fix=(
                    "Review the device's settings and disable features/services "
                    "you don't use. If it's an old device you no longer need, "
                    "retire it."
                ),
                evidence=f"{len(open_ports)} open ports",
            )
        )

    return out


def evaluate(hosts: List[Host]) -> List[Host]:
    for host in hosts:
        evaluate_host(host)
    return hosts


def score_and_grade(hosts: List[Host], network_findings=None) -> tuple:
    """Return ``(score, grade)`` for the whole network.

    Score starts at 100 and loses points per finding, weighted by severity.
    ``network_findings`` are non-host findings (e.g. weak Wi-Fi) that also
    count toward the grade.
    """
    penalty = 0.0
    for host in hosts:
        for f in host.findings:
            penalty += _SEVERITY_PENALTY[f.severity]
    for f in network_findings or []:
        penalty += _SEVERITY_PENALTY[f.severity]

    score = max(0, round(100 - penalty))
    return score, grade_for_score(score)


def grade_for_score(score: int) -> str:
    if score >= 95:
        return "A"
    if score >= 85:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"


def rescore(result: ScanResult) -> ScanResult:
    """Recompute the score/grade from the result's current findings."""
    result.score, result.grade = score_and_grade(
        result.hosts, result.network_findings
    )
    return result


def finalize(result: ScanResult) -> ScanResult:
    """Evaluate every host, then compute the overall score/grade on the result."""
    evaluate(result.hosts)
    return rescore(result)
