import io
import json

import iotpwned.cve_online as online
from iotpwned.cve_online import (
    OnlineCVE,
    derive_keywords,
    enrich,
    parse_nvd_response,
    query_nvd,
)
from iotpwned.models import Host, Severity
from iotpwned.risk import evaluate_host

SAMPLE = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2021-36260",
            "descriptions": [{"lang": "en", "value": "Command injection in web server."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        }},
        {"cve": {
            "id": "CVE-2017-7921",
            "descriptions": [{"lang": "es", "value": "spanish"}, {"lang": "en", "value": "Auth bypass."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
        }},
        {"cve": {
            "id": "CVE-2016-0001",
            "descriptions": [{"lang": "en", "value": "A minor issue."}],
            "metrics": {"cvssMetricV2": [{"baseSeverity": "LOW", "cvssData": {"baseScore": 3.5}}]},
        }},
    ]
}


def _host(device_type="Unknown device", vendor=None):
    return Host(ip="192.168.1.77", vendor=vendor, device_type=device_type)


def test_derive_keywords_only_known_brands():
    hosts = [
        _host(device_type="Hikvision IP camera / DVR"),
        _host(vendor="Zhejiang Dahua", device_type="IP camera / DVR"),
        _host(device_type="Unknown IoT device"),
    ]
    km = derive_keywords(hosts)
    assert set(km) == {"Hikvision", "Dahua"}
    # unknown device contributes nothing that would be sent
    assert all(kw in ("Hikvision", "Dahua") for kw in km)


def test_derive_keywords_dedupes_brand_aliases():
    # "archer" and "tp-link" both map to the single keyword "TP-Link"
    hosts = [_host(device_type="TP-Link router", vendor="TP-Link Archer AX21")]
    km = derive_keywords(hosts)
    assert list(km) == ["TP-Link"]


def test_parse_sorts_by_score_and_limits():
    cves = parse_nvd_response(SAMPLE, limit=2)
    assert [c.cve_id for c in cves] == ["CVE-2017-7921", "CVE-2021-36260"]
    assert cves[0].severity is Severity.CRITICAL
    assert cves[0].url.endswith("CVE-2017-7921")


def test_parse_picks_english_description():
    cves = parse_nvd_response(SAMPLE, limit=5)
    bypass = next(c for c in cves if c.cve_id == "CVE-2017-7921")
    assert bypass.description == "Auth bypass."


def test_parse_v2_only_severity_fallback():
    cves = parse_nvd_response(SAMPLE, limit=5)
    minor = next(c for c in cves if c.cve_id == "CVE-2016-0001")
    assert minor.severity is Severity.LOW


def test_parse_empty_payload():
    assert parse_nvd_response({}, limit=5) == []


def test_query_nvd_uses_http_and_parses(monkeypatch):
    captured = {}

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        return _Resp(json.dumps(SAMPLE).encode())

    monkeypatch.setattr(online.urllib.request, "urlopen", fake_urlopen)
    cves = query_nvd("Hikvision", limit=3, timeout=5.0)
    assert "keywordSearch=Hikvision" in captured["url"]
    assert captured["timeout"] == 5.0
    assert cves[0].cve_id == "CVE-2017-7921"


def test_query_nvd_network_error_returns_empty(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("network down")

    monkeypatch.setattr(online.urllib.request, "urlopen", boom)
    assert query_nvd("Hikvision") == []


def test_enrich_attaches_and_dedupes_offline(monkeypatch):
    host = _host(device_type="Hikvision IP camera / DVR")
    evaluate_host(host)  # offline pass adds CVE-2021-36260 and CVE-2017-7921
    assert any("CVE-2021-36260" in f.rule_id for f in host.findings)

    def fake_query(keyword, **kw):
        return [
            OnlineCVE("CVE-2017-7921", 10.0, Severity.CRITICAL, "dup", "u"),  # already offline
            OnlineCVE("CVE-2099-1111", 8.1, Severity.HIGH, "new one", "u2"),
        ]

    monkeypatch.setattr(online, "query_nvd", fake_query)
    km = {"Hikvision": [host]}
    added = enrich(km, delay=0)

    assert added == 1  # the duplicate was skipped
    rule_ids = [f.rule_id for f in host.findings]
    assert "cve-online-CVE-2099-1111" in rule_ids
    assert rule_ids.count("cve-online-CVE-2017-7921") == 0


def test_enrich_no_keywords_adds_nothing(monkeypatch):
    monkeypatch.setattr(online, "query_nvd", lambda *a, **k: [])
    assert enrich({}, delay=0) == 0
