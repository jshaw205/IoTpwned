from iotpwned import webui
from iotpwned.models import Host, OpenPort, ScanResult
from iotpwned.risk import finalize

TOKEN = "test-token-123"


def _fake_result(form=None):
    host = Host(ip="192.168.1.30", device_type="Hikvision IP camera / DVR",
                open_ports=[OpenPort(port=23, service="Telnet")])
    result = ScanResult(subnet="192.168.1.0/24", hosts=[host])
    finalize(result)
    return result


def test_is_local_host():
    assert webui.is_local_host("127.0.0.1:8765")
    assert webui.is_local_host("localhost:8765")
    assert webui.is_local_host("localhost")
    assert webui.is_local_host("[::1]:8765")
    assert not webui.is_local_host("evil.example.com:8765")
    assert not webui.is_local_host("192.168.1.5:8765")
    assert not webui.is_local_host("")


def test_parse_form():
    form = webui.parse_form(b"token=abc&consent=on&cidr=192.168.1.0%2F24")
    assert form["token"] == "abc"
    assert form["consent"] == "on"
    assert form["cidr"] == "192.168.1.0/24"


def test_index_contains_token_and_controls():
    page = webui.build_index(TOKEN)
    assert TOKEN in page
    assert 'name="consent"' in page
    assert 'name="online_cve"' in page
    assert "Only scan networks you own" in page


def test_get_root_and_favicon_and_404():
    status, ctype, body = webui.process_get("/", TOKEN)
    assert status == 200 and TOKEN.encode() in body
    assert webui.process_get("/favicon.ico", TOKEN)[0] == 204
    assert webui.process_get("/nope", TOKEN)[0] == 404


def test_post_rejects_non_local_host():
    status, _, _ = webui.process_post(
        "/scan", "evil.com", b"token=" + TOKEN.encode() + b"&consent=on",
        TOKEN, _fake_result)
    assert status == 403


def test_post_rejects_bad_token():
    status, _, _ = webui.process_post(
        "/scan", "127.0.0.1:8765", b"token=wrong&consent=on", TOKEN, _fake_result)
    assert status == 403


def test_post_requires_consent():
    body = b"token=" + TOKEN.encode()  # no consent
    status, ctype, out = webui.process_post(
        "/scan", "127.0.0.1:8765", body, TOKEN, _fake_result)
    assert status == 400
    assert b"confirm you own" in out.lower() or b"confirm you own" in out


def test_post_valid_runs_scan_and_returns_report():
    body = b"token=" + TOKEN.encode() + b"&consent=on"
    called = {}

    def scan_fn(form):
        called["yes"] = True
        return _fake_result(form)

    status, ctype, out = webui.process_post(
        "/scan", "127.0.0.1:8765", body, TOKEN, scan_fn)
    assert status == 200
    assert called.get("yes")
    text = out.decode()
    assert "IoTpwned report" in text or "NETWORK" in text or "grade" in text.lower()
    assert "Run another scan" in text
    assert "192.168.1.30" in text


def test_post_scan_runtime_error_shows_message():
    def scan_fn(form):
        raise RuntimeError("Could not auto-detect the local subnet.")

    body = b"token=" + TOKEN.encode() + b"&consent=on"
    status, ctype, out = webui.process_post(
        "/scan", "127.0.0.1:8765", body, TOKEN, scan_fn)
    assert status == 400
    assert b"auto-detect" in out


def test_post_wrong_path_404():
    assert webui.process_post("/x", "127.0.0.1", b"", TOKEN, _fake_result)[0] == 404
