import iotpwned.credcheck as cc
from iotpwned.models import Host, OpenPort, ScanResult, Severity
from iotpwned.risk import finalize


def _host(**kw):
    return Host(ip=kw.pop("ip", "192.168.1.1"), **kw)


def test_build_cred_list_brand_first_and_capped():
    host = _host(device_type="Hikvision IP camera / DVR")
    pairs = cc.build_cred_list(host)
    assert ("admin", "12345") in pairs          # brand default
    assert ("admin", "admin") in pairs          # universal
    assert pairs[0] == ("admin", "12345")       # brand comes first
    assert len(pairs) <= 8


def test_is_candidate():
    assert cc.is_candidate(_host(is_gateway=True))
    assert cc.is_candidate(_host(device_type="TP-Link router"))
    assert cc.is_candidate(_host(open_ports=[OpenPort(port=8080, service="x")]))
    assert not cc.is_candidate(_host(device_type="Unknown device"))


def test_basic_auth_realm(monkeypatch):
    def fake(url, timeout, auth=None):
        return fake.ret
    monkeypatch.setattr(cc, "_request", fake)

    fake.ret = (401, {"WWW-Authenticate": "Basic realm=\"Router\""})
    assert cc.basic_auth_realm("http://x/", 3) is True
    fake.ret = (401, {"WWW-Authenticate": "Digest realm=x"})
    assert cc.basic_auth_realm("http://x/", 3) is False
    fake.ret = (200, {})
    assert cc.basic_auth_realm("http://x/", 3) is False
    fake.ret = (None, None)
    assert cc.basic_auth_realm("http://x/", 3) is None


def test_try_default_creds_finds_working_pair(monkeypatch):
    def fake(url, timeout, auth=None):
        return (200, {}) if auth == ("admin", "admin") else (401, {})
    monkeypatch.setattr(cc, "_request", fake)
    got = cc.try_default_creds("http://x/", [("root", "root"), ("admin", "admin")],
                               timeout=1, delay=0)
    assert got == ("admin", "admin")


def test_try_default_creds_none_when_all_rejected(monkeypatch):
    monkeypatch.setattr(cc, "_request", lambda u, t, auth=None: (401, {}))
    assert cc.try_default_creds("http://x/", [("a", "b")], timeout=1, delay=0) is None


def test_try_default_creds_stops_on_lockout(monkeypatch):
    calls = {"n": 0}

    def fake(url, timeout, auth=None):
        calls["n"] += 1
        return (429, {})

    monkeypatch.setattr(cc, "_request", fake)
    result = cc.try_default_creds("http://x/", [("a", "b"), ("c", "d")],
                                  timeout=1, delay=0)
    assert result is None
    assert calls["n"] == 1  # bailed after the lockout signal


def test_check_host_flags_default_password(monkeypatch):
    monkeypatch.setattr(cc, "basic_auth_realm", lambda url, timeout: True)
    monkeypatch.setattr(cc, "try_default_creds",
                        lambda url, pairs, timeout: ("admin", "admin"))
    host = _host(is_gateway=True, device_type="TP-Link router")
    findings, tested = cc.check_host_credentials(host)
    assert tested is True
    assert findings and findings[0].severity is Severity.CRITICAL
    assert "default password" in findings[0].title.lower()


def test_check_host_clean_when_no_default_works(monkeypatch):
    monkeypatch.setattr(cc, "basic_auth_realm", lambda url, timeout: True)
    monkeypatch.setattr(cc, "try_default_creds", lambda url, pairs, timeout: None)
    findings, tested = cc.check_host_credentials(_host(is_gateway=True))
    assert tested is True and findings == []


def test_check_host_skips_non_candidate():
    findings, tested = cc.check_host_credentials(_host(device_type="Unknown device"))
    assert findings == [] and tested is False


def test_check_host_skips_form_login(monkeypatch):
    # Basic-auth detection returns False (form login / open) -> no attempts.
    monkeypatch.setattr(cc, "basic_auth_realm", lambda url, timeout: False)
    called = {"n": 0}
    monkeypatch.setattr(cc, "try_default_creds",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    findings, tested = cc.check_host_credentials(_host(is_gateway=True))
    assert findings == [] and tested is False and called["n"] == 0


def test_cred_finding_lowers_grade(monkeypatch):
    from iotpwned import engine
    monkeypatch.setattr(cc, "basic_auth_realm", lambda url, timeout: True)
    monkeypatch.setattr(cc, "try_default_creds",
                        lambda url, pairs, timeout: ("admin", "admin"))
    host = _host(is_gateway=True, device_type="TP-Link router")
    result = ScanResult(subnet="192.168.1.0/24", hosts=[host])
    finalize(result)
    before = result.score
    tested, weak = engine.apply_cred_check(result)
    assert tested == 1 and weak == 1
    assert result.score < before
    assert any(f.rule_id.startswith("weak-cred-") for f in host.findings)
