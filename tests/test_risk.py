from iotpwned.models import Host, OpenPort, ScanResult, Severity
from iotpwned.risk import (
    evaluate_host,
    finalize,
    grade_for_score,
    score_and_grade,
)


def _host(*ports):
    return Host(ip="192.168.1.50",
                open_ports=[OpenPort(port=p, service="x") for p in ports])


def test_telnet_is_critical():
    host = _host(23)
    findings = evaluate_host(host)
    assert any(f.severity is Severity.CRITICAL for f in findings)
    telnet = next(f for f in findings if f.port == 23)
    assert "telnet" in telnet.why.lower() or "telnet" in telnet.title.lower()
    assert telnet.fix  # every finding must carry a fix


def test_clean_host_has_no_findings():
    host = _host()
    assert evaluate_host(host) == []
    assert host.worst_severity is Severity.INFO


def test_findings_sorted_worst_first():
    host = _host(22, 23, 8080)  # low, critical, medium
    findings = evaluate_host(host)
    severities = [f.severity.value for f in findings]
    assert severities == sorted(severities, reverse=True)
    assert findings[0].severity is Severity.CRITICAL


def test_multiple_default_cred_services_triggers_cross_rule():
    host = _host(23, 5900)  # both default-cred-prone
    findings = evaluate_host(host)
    assert any(f.rule_id == "many-default-cred-services" for f in findings)


def test_large_attack_surface_rule():
    host = _host(21, 22, 23, 445, 5900, 8080)
    findings = evaluate_host(host)
    assert any(f.rule_id == "large-attack-surface" for f in findings)


def test_every_finding_has_why_and_fix():
    host = _host(21, 23, 445, 554, 7547, 37777)
    for f in evaluate_host(host):
        assert f.why.strip(), f"{f.rule_id} missing why"
        assert f.fix.strip(), f"{f.rule_id} missing fix"


def test_grade_boundaries():
    assert grade_for_score(100) == "A"
    assert grade_for_score(95) == "A"
    assert grade_for_score(94) == "B"
    assert grade_for_score(85) == "B"
    assert grade_for_score(70) == "C"
    assert grade_for_score(55) == "D"
    assert grade_for_score(54) == "F"
    assert grade_for_score(0) == "F"


def test_clean_network_scores_A():
    result = ScanResult(subnet="192.168.1.0/24", hosts=[_host(), _host()])
    finalize(result)
    assert result.score == 100
    assert result.grade == "A"


def test_critical_finding_drags_grade_down():
    result = ScanResult(subnet="192.168.1.0/24", hosts=[_host(23)])
    finalize(result)
    assert result.grade in ("C", "D", "F")
    assert result.score < 85


def test_score_never_negative():
    # Pile on many criticals; score floors at 0, grade F.
    host = _host(23, 2323, 32764)
    evaluate_host(host)  # scoring reads host.findings, so evaluate first
    score, grade = score_and_grade([host])
    assert score >= 0
    assert grade == "F"
