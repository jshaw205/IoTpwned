"""Multi-subnet / multi-VLAN scanning: parsing, engine merge, and report grouping."""

from iotpwned import cli, engine, webui
from iotpwned.models import Host, OpenPort, ScanResult
from iotpwned.report import render_console, render_html
from iotpwned.risk import finalize


# ---------------------------------------------------------------------------
# Parsing: --cidr (CLI), the web form field, and the engine's target resolver
# ---------------------------------------------------------------------------

def test_cli_parse_cidrs_repeated_and_comma_separated():
    # argparse append gives a list; each entry may itself be comma/space separated.
    assert cli._parse_cidrs(["192.168.1.0/24", "192.168.20.0/24"]) == [
        "192.168.1.0/24", "192.168.20.0/24"]
    assert cli._parse_cidrs(["192.168.1.0/24,192.168.20.0/24"]) == [
        "192.168.1.0/24", "192.168.20.0/24"]
    assert cli._parse_cidrs(["10.0.0.0/24 10.0.1.0/24"]) == [
        "10.0.0.0/24", "10.0.1.0/24"]


def test_cli_parse_cidrs_dedupes_and_handles_empty():
    assert cli._parse_cidrs(["10.0.0.0/24", "10.0.0.0/24"]) == ["10.0.0.0/24"]
    assert cli._parse_cidrs([]) is None
    assert cli._parse_cidrs(None) is None
    assert cli._parse_cidrs(["", "  "]) is None


def test_webui_split_cidrs():
    assert webui._split_cidrs("192.168.1.0/24, 192.168.20.0/24") == [
        "192.168.1.0/24", "192.168.20.0/24"]
    assert webui._split_cidrs("") is None
    assert webui._split_cidrs(None) is None


def test_cli_cidr_flag_appends(monkeypatch):
    args = cli.build_parser().parse_args(
        ["--cidr", "192.168.1.0/24", "--cidr", "192.168.20.0/24"])
    assert args.cidr == ["192.168.1.0/24", "192.168.20.0/24"]


def test_engine_resolve_targets():
    assert engine._resolve_targets(None, ["a/24", "b/24"]) == ["a/24", "b/24"]
    assert engine._resolve_targets("a/24", None) == ["a/24"]
    # both provided: cidrs first, then cidr, de-duplicated
    assert engine._resolve_targets("a/24", ["a/24", "b/24"]) == ["a/24", "b/24"]


# ---------------------------------------------------------------------------
# Engine merge: each subnet's hosts are tagged and combined into one result
# ---------------------------------------------------------------------------

def test_run_pipeline_merges_subnets_and_tags_hosts(monkeypatch):
    def fake_discover(cidr, **kw):
        # Return one host per subnet, keyed off the CIDR so we can tell them apart.
        last = cidr.split(".")[2]
        return [Host(ip=f"10.0.{last}.5")]

    monkeypatch.setattr(engine, "discover_hosts", fake_discover)
    monkeypatch.setattr(engine, "scan_hosts", lambda hosts, **kw: None)
    monkeypatch.setattr(engine, "fingerprint_hosts", lambda hosts: None)

    result = engine.run_pipeline(
        cidrs=["10.0.1.0/24", "10.0.2.0/24"], do_wifi=False)

    assert result.subnets == ["10.0.1.0/24", "10.0.2.0/24"]
    assert result.subnet == "10.0.1.0/24, 10.0.2.0/24"
    assert [h.ip for h in result.hosts] == ["10.0.1.5", "10.0.2.5"]
    # Every host carries the subnet it was found on.
    assert result.hosts[0].subnet == "10.0.1.0/24"
    assert result.hosts[1].subnet == "10.0.2.0/24"


def test_run_pipeline_calls_subnet_start_per_subnet(monkeypatch):
    monkeypatch.setattr(engine, "discover_hosts", lambda cidr, **kw: [])
    monkeypatch.setattr(engine, "scan_hosts", lambda hosts, **kw: None)
    monkeypatch.setattr(engine, "fingerprint_hosts", lambda hosts: None)

    seen = []
    engine.run_pipeline(
        cidrs=["10.0.1.0/24", "10.0.2.0/24"],
        do_wifi=False,
        on_subnet_start=lambda cidr, idx, total: seen.append((cidr, idx, total)),
    )
    assert seen == [("10.0.1.0/24", 0, 2), ("10.0.2.0/24", 1, 2)]


# ---------------------------------------------------------------------------
# Reporting: hosts are grouped by subnet and the ARP caveat is shown
# ---------------------------------------------------------------------------

def _multi_result():
    a = Host(ip="192.168.1.30", subnet="192.168.1.0/24",
             open_ports=[OpenPort(port=23, service="Telnet")])
    b = Host(ip="192.168.20.40", subnet="192.168.20.0/24")
    result = ScanResult(
        subnet="192.168.1.0/24, 192.168.20.0/24",
        subnets=["192.168.1.0/24", "192.168.20.0/24"],
        hosts=[a, b], duration_seconds=2.0, finished_at="2026-07-11T10:00:00")
    finalize(result)
    return result


def test_console_groups_by_subnet_with_caveat():
    text = render_console(_multi_result(), use_color=False)
    assert "Subnet 192.168.1.0/24 — 1 device(s)" in text
    assert "Subnet 192.168.20.0/24 — 1 device(s)" in text
    assert "2 subnets" in text
    assert "ARP" in text  # the remote-subnet fingerprinting caveat


def test_html_groups_by_subnet_with_caveat():
    html = render_html(_multi_result())
    assert "192.168.1.0/24" in html
    assert "192.168.20.0/24" in html
    assert "192.168.1.30" in html
    assert "192.168.20.40" in html
    assert "ARP" in html


def test_single_subnet_report_unchanged():
    host = Host(ip="192.168.1.30", subnet="192.168.1.0/24")
    result = ScanResult(subnet="192.168.1.0/24", subnets=["192.168.1.0/24"],
                        hosts=[host])
    finalize(result)
    text = render_console(result, use_color=False)
    # No per-subnet grouping header or caveat for an ordinary single-subnet scan.
    assert "— 1 device(s)" not in text
    assert "ARP" not in text
    assert "Devices &amp; findings" in render_html(result)
