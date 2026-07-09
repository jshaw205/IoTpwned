from iotpwned.cve import cve_findings, match_cves
from iotpwned.cve_data import CVE_SNAPSHOT
from iotpwned.models import Host, OpenPort, Severity
from iotpwned.risk import evaluate_host


def _host(vendor=None, device_type="Unknown device", banners=()):
    host = Host(ip="192.168.1.55", vendor=vendor, device_type=device_type)
    host.open_ports = [OpenPort(port=80, service="HTTP", banner=b) for b in banners]
    return host


def test_snapshot_is_wellformed():
    ids = [rec.cve_id for rec in CVE_SNAPSHOT]
    assert len(ids) == len(set(ids)), "duplicate CVE ids"
    for rec in CVE_SNAPSHOT:
        assert rec.cve_id.startswith("CVE-")
        assert rec.match_any, f"{rec.cve_id} has no match tokens"
        assert all(t == t.lower() for t in rec.match_any), "tokens must be lowercase"
        assert rec.summary and rec.fix
        assert isinstance(rec.severity, Severity)


def test_matches_hikvision_by_device_type():
    host = _host(device_type="Hikvision IP camera / DVR")
    ids = {rec.cve_id for rec in match_cves(host)}
    assert "CVE-2021-36260" in ids
    assert "CVE-2017-7921" in ids


def test_matches_by_vendor_string():
    host = _host(vendor="Zhejiang Dahua", device_type="IP camera / DVR")
    ids = {rec.cve_id for rec in match_cves(host)}
    assert "CVE-2021-33044" in ids


def test_matches_by_banner():
    host = _host(device_type="Router", banners=["Server: RomPager/4.07 UPnP/1.0"])
    ids = {rec.cve_id for rec in match_cves(host)}
    assert "CVE-2014-9222" in ids


def test_no_match_for_generic_device():
    host = _host(device_type="Unknown device")
    assert match_cves(host) == []


def test_empty_haystack_returns_no_matches():
    host = Host(ip="10.0.0.1")  # no vendor, device_type default, no ports
    host.device_type = ""
    assert match_cves(host) == []


def test_cve_findings_carry_reference_and_id():
    host = _host(device_type="Hikvision IP camera / DVR")
    findings = cve_findings(host)
    assert findings
    f = findings[0]
    assert f.rule_id.startswith("cve-CVE-")
    assert "CVE-" in f.title
    assert f.reference.startswith("http")
    assert f.fix.strip()
    # framed as "verify firmware", not a confirmed exploit
    assert "firmware" in f.why.lower()


def test_cve_findings_flow_through_risk_engine():
    host = _host(device_type="Hikvision IP camera / DVR")
    findings = evaluate_host(host)
    cve_ids = {f.rule_id for f in findings if f.rule_id.startswith("cve-")}
    assert "cve-CVE-2021-36260" in cve_ids
    # findings remain sorted worst-first
    sev = [f.severity.value for f in findings]
    assert sev == sorted(sev, reverse=True)


def test_cve_lowers_the_grade():
    from iotpwned.models import ScanResult
    from iotpwned.risk import finalize

    clean = ScanResult(subnet="x", hosts=[_host(device_type="Unknown device")])
    finalize(clean)

    risky = ScanResult(subnet="x",
                       hosts=[_host(device_type="Hikvision IP camera / DVR")])
    finalize(risky)

    assert risky.score < clean.score
