import io
import json
import urllib.error

import iotpwned.wan as wan
from iotpwned.models import Host, ScanResult, Severity, WanInfo
from iotpwned.risk import score_and_grade
from iotpwned.wan import (
    check_wan,
    evaluate_wan,
    get_public_ip,
    mask_ip,
    query_internetdb,
)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_mask_ip():
    assert mask_ip("203.0.113.45") == "203.0.x.x"
    assert mask_ip(None) is None
    assert mask_ip("not-an-ip") == "not-an-ip"


def test_get_public_ip(monkeypatch):
    monkeypatch.setattr(wan.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp(b"203.0.113.45\n"))
    assert get_public_ip() == "203.0.113.45"


def test_get_public_ip_rejects_garbage(monkeypatch):
    monkeypatch.setattr(wan.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp(b"nonsense"))
    assert get_public_ip() is None


def test_query_internetdb_success(monkeypatch):
    payload = {"ip": "203.0.113.45", "ports": [80, 7547], "vulns": ["CVE-2020-1"]}
    monkeypatch.setattr(wan.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp(json.dumps(payload).encode()))
    data = query_internetdb("203.0.113.45")
    assert data["ports"] == [80, 7547]


def test_query_internetdb_404_means_empty(monkeypatch):
    def raise_404(req, timeout=None):
        raise urllib.error.HTTPError("u", 404, "Not Found", {}, None)

    monkeypatch.setattr(wan.urllib.request, "urlopen", raise_404)
    assert query_internetdb("203.0.113.45") == {}


def test_query_internetdb_error_returns_none(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("down")

    monkeypatch.setattr(wan.urllib.request, "urlopen", boom)
    assert query_internetdb("203.0.113.45") is None


def test_evaluate_wan_flags_open_ports_and_vulns():
    info = WanInfo(checked=True, public_ip="203.0.113.45",
                   open_ports=[80, 23], vulns=["CVE-2021-1", "CVE-2021-2"])
    findings = evaluate_wan(info)
    ids = {f.rule_id for f in findings}
    assert "wan-port-23" in ids and "wan-port-80" in ids
    assert "wan-known-vulns" in ids
    telnet = next(f for f in findings if f.rule_id == "wan-port-23")
    assert telnet.severity is Severity.CRITICAL      # remote-admin port
    web = next(f for f in findings if f.rule_id == "wan-port-80")
    assert web.severity is Severity.HIGH


def test_evaluate_wan_clean_when_nothing_open():
    info = WanInfo(checked=True, public_ip="203.0.113.45")
    assert evaluate_wan(info) == []


def test_evaluate_wan_skips_when_not_checked():
    assert evaluate_wan(WanInfo(checked=False)) == []


def test_check_wan_no_public_ip(monkeypatch):
    monkeypatch.setattr(wan, "get_public_ip", lambda timeout=15.0: None)
    info, findings = check_wan()
    assert not info.supported and findings == []


def test_check_wan_end_to_end(monkeypatch):
    monkeypatch.setattr(wan, "get_public_ip", lambda timeout=15.0: "203.0.113.45")
    monkeypatch.setattr(wan, "query_internetdb",
                        lambda ip, timeout=15.0: {"ports": [3389], "vulns": []})
    info, findings = check_wan()
    assert info.checked and info.public_ip == "203.0.113.45"
    assert info.open_ports == [3389]
    assert findings and findings[0].severity is Severity.CRITICAL


def test_wan_findings_count_toward_grade():
    info = WanInfo(checked=True, public_ip="203.0.113.45", open_ports=[3389])
    findings = evaluate_wan(info)
    clean, _ = score_and_grade([Host(ip="10.0.0.1")], [])
    risky, grade = score_and_grade([Host(ip="10.0.0.1")], findings)
    assert risky < clean
