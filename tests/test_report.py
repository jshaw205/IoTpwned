from iotpwned.models import Finding, Host, OpenPort, ScanResult, Severity
from iotpwned.report import render_console, render_html
from iotpwned.risk import finalize


def _sample_result():
    cam = Host(
        ip="192.168.1.30",
        mac="44:19:B6:00:00:01",
        device_type="Hikvision IP camera / DVR",
        open_ports=[
            OpenPort(port=23, service="Telnet"),
            OpenPort(port=554, service="RTSP"),
        ],
    )
    clean = Host(ip="192.168.1.40", device_type="Unknown device")
    result = ScanResult(subnet="192.168.1.0/24", hosts=[cam, clean],
                        duration_seconds=3.2, finished_at="2026-07-08T12:00:00")
    finalize(result)
    return result


def test_console_report_mentions_grade_and_findings():
    result = _sample_result()
    text = render_console(result, use_color=False)
    assert "NETWORK GRADE" in text
    assert result.grade in text
    assert "Telnet" in text
    assert "Fix:" in text


def test_console_report_no_ansi_when_color_off():
    text = render_console(_sample_result(), use_color=False)
    assert "\033[" not in text


def test_html_report_is_self_contained():
    html = render_html(_sample_result())
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    # No external asset references (privacy-first, offline).
    assert "http://" not in html
    assert "https://" not in html
    assert "src=" not in html


def test_html_report_escapes_content():
    host = Host(ip="1.2.3.4", device_type="<script>evil()</script>")
    host.findings = [
        Finding(rule_id="x", title="<b>xss</b>", severity=Severity.HIGH,
                why="w", fix="f")
    ]
    result = ScanResult(subnet="1.2.3.0/24", hosts=[host])
    finalize(result)  # recompute won't clobber manual findings? it will re-evaluate
    # Manually re-set findings after finalize for this escaping test:
    host.findings = [
        Finding(rule_id="x", title="<b>xss</b>", severity=Severity.HIGH,
                why="w", fix="f")
    ]
    html = render_html(result)
    assert "<script>evil" not in html
    assert "&lt;script&gt;" in html


def test_html_contains_all_hosts():
    result = _sample_result()
    html = render_html(result)
    for host in result.hosts:
        assert host.ip in html
