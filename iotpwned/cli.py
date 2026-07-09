"""Command-line interface for IoTpwned.

    iotpwned                         # auto-detect subnet, scan, print report
    iotpwned --cidr 192.168.1.0/24   # scan a specific range
    iotpwned --html report.html      # also write a shareable HTML report
    iotpwned --yes-i-own-this-network  # skip the interactive consent prompt

Pipeline: discovery -> port scan -> fingerprint -> risk score -> report.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
from typing import List, Optional

import os

from . import __version__, cve_online, wifi
from .discovery import default_subnet, discover_hosts
from .fingerprint import fingerprint_hosts
from .models import ScanResult
from .report import render_console, render_html
from .risk import finalize, rescore
from .scanner import scan_hosts

CONSENT_TEXT = """\
┌────────────────────────────────────────────────────────────────┐
│  IoTpwned — home network security scanner                     │
│                                                                │
│  This tool scans the local network for exposed IoT/router      │
│  services and explains how to fix them. Everything runs        │
│  locally; no data leaves this machine.                         │
│                                                                │
│  Only scan networks you OWN or have PERMISSION to test.        │
│  Scanning other people's networks is illegal in most places.   │
│  IoTpwned never attempts any password or login.               │
└────────────────────────────────────────────────────────────────┘
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iotpwned",
        description="Privacy-first home network IoT security scanner.",
        epilog="Only scan networks you own or have permission to test.",
    )
    p.add_argument("--cidr", metavar="CIDR",
                   help="Subnet to scan, e.g. 192.168.1.0/24 "
                        "(default: auto-detect).")
    p.add_argument("--html", metavar="PATH",
                   help="Write a shareable HTML report to PATH.")
    p.add_argument("--json", metavar="PATH",
                   help="Write machine-readable JSON results to PATH.")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Per-port TCP connect timeout in seconds (default 1.0).")
    p.add_argument("--ping-timeout", type=int, default=700,
                   help="Ping timeout per host in ms (default 700).")
    p.add_argument("--no-ping", action="store_true",
                   help="Skip the ping sweep; use only the existing ARP cache.")
    p.add_argument("--no-resolve", action="store_true",
                   help="Skip reverse-DNS hostname lookups (faster).")
    p.add_argument("--no-wifi", action="store_true",
                   help="Skip the local Wi-Fi encryption check.")
    p.add_argument("--ports", metavar="LIST",
                   help="Comma-separated ports to scan instead of the "
                        "built-in risky-port list.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable coloured console output.")
    p.add_argument("--yes-i-own-this-network", action="store_true",
                   help="Confirm you own/are authorised to scan this network "
                        "and skip the interactive consent prompt.")
    p.add_argument("--online-cve", action="store_true",
                   help="Also look up known CVEs for detected device brands "
                        "against the online NIST NVD API. OFF by default and "
                        "asks for consent first, since it sends brand names "
                        "(only) over the internet.")
    p.add_argument("--yes-online-cve", action="store_true",
                   help="Pre-consent to the online CVE lookup (implies "
                        "--online-cve) and skip its interactive prompt.")
    p.add_argument("--online-cve-limit", type=int, default=5, metavar="N",
                   help="Max CVEs to report per device brand from the online "
                        "lookup (default 5).")
    p.add_argument("--nvd-api-key", metavar="KEY", default=None,
                   help="Optional NVD API key for a higher rate limit "
                        "(falls back to the NVD_API_KEY environment variable).")
    p.add_argument("--version", action="version",
                   version=f"IoTpwned {__version__}")
    return p


def _confirm_consent(assume_yes: bool) -> bool:
    print(CONSENT_TEXT)
    if assume_yes:
        print("Authorisation confirmed via --yes-i-own-this-network.\n")
        return True
    if not sys.stdin.isatty():
        print("Refusing to scan: no terminal to confirm consent. "
              "Re-run with --yes-i-own-this-network if you own this network.")
        return False
    try:
        answer = input("Do you own or have permission to scan this network? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def _confirm_online_consent(keywords: List[str], assume_yes: bool) -> bool:
    """Second, separate consent gate specifically for the online API call.

    Shows exactly which brand keywords would be sent, and to where, before
    anything leaves the machine.
    """
    kw = ", ".join(keywords)
    print()
    print("  ── Online CVE lookup ─────────────────────────────────────────")
    print("  This will contact the NIST NVD API (services.nvd.nist.gov) and")
    print("  send ONLY these device brand keywords:")
    print(f"      {kw}")
    print("  No IP addresses, MAC addresses, hostnames, or banners are sent.")
    print("  ──────────────────────────────────────────────────────────────")
    if assume_yes:
        print("  Consent confirmed via --yes-online-cve.\n")
        return True
    if not sys.stdin.isatty():
        print("  Skipping online lookup: no terminal to confirm consent. "
              "Re-run with --yes-online-cve to allow it.\n")
        return False
    try:
        answer = input("  Send these brand keywords to the NVD API? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def _maybe_online_cve(result: ScanResult, args: argparse.Namespace) -> None:
    """If enabled and consented, enrich findings from the online NVD API."""
    if not (args.online_cve or args.yes_online_cve):
        return

    keyword_map = cve_online.derive_keywords(result.hosts)
    if not keyword_map:
        print("\n  Online CVE lookup: no recognised device brands to look up.")
        return

    if not _confirm_online_consent(list(keyword_map), args.yes_online_cve):
        return

    api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY")
    added = cve_online.enrich(
        keyword_map,
        limit=args.online_cve_limit,
        api_key=api_key,
        progress=_progress("NVD lookup"),
    )
    # Findings changed, so the score/grade must be recomputed.
    rescore(result)
    print(f"  Online CVE lookup added {added} finding(s).")


def _parse_ports(spec: Optional[str]) -> Optional[List[int]]:
    if not spec:
        return None
    ports: List[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            port = int(chunk)
        except ValueError:
            raise SystemExit(f"Invalid port: {chunk!r}")
        if not 1 <= port <= 65535:
            raise SystemExit(f"Port out of range: {port}")
        ports.append(port)
    return ports or None


def _progress(stage: str):
    def cb(done: int, total: int, current: str) -> None:
        pct = int(done / total * 100) if total else 100
        sys.stderr.write(f"\r  {stage}: {done}/{total} ({pct}%)   ")
        sys.stderr.flush()
        if done >= total:
            sys.stderr.write("\n")
    return cb


def run_scan(args: argparse.Namespace) -> ScanResult:
    ports = _parse_ports(args.ports)

    cidr = args.cidr or default_subnet()
    if not cidr:
        raise SystemExit(
            "Could not auto-detect your subnet. Pass one with "
            "--cidr, e.g. --cidr 192.168.1.0/24"
        )

    started = time.time()
    started_iso = datetime.datetime.now().isoformat(timespec="seconds")

    print(f"\nScanning {cidr} ...\n")

    hosts = discover_hosts(
        cidr=cidr,
        timeout_ms=args.ping_timeout,
        do_ping=not args.no_ping,
        resolve_names=not args.no_resolve,
        progress=None if args.no_ping else _progress("Pinging"),
    )
    print(f"  Found {len(hosts)} device(s). Scanning ports ...")

    scan_hosts(hosts, ports=ports, timeout=args.timeout,
               progress=_progress("Port-scanning"))

    fingerprint_hosts(hosts)

    result = ScanResult(
        subnet=cidr,
        hosts=hosts,
        started_at=started_iso,
        finished_at=datetime.datetime.now().isoformat(timespec="seconds"),
        duration_seconds=time.time() - started,
    )

    if not args.no_wifi:
        info, wifi_findings = wifi.check_wifi()
        result.wifi = info
        result.network_findings.extend(wifi_findings)

    finalize(result)
    return result


def _finding_json(f) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.label,
        "why": f.why,
        "fix": f.fix,
        "port": f.port,
        "reference": f.reference,
    }


def _write_json(result: ScanResult, path: str) -> None:
    payload = {
        "subnet": result.subnet,
        "grade": result.grade,
        "score": result.score,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "duration_seconds": round(result.duration_seconds, 2),
        "wifi": (
            {
                "supported": result.wifi.supported,
                "connected": result.wifi.connected,
                "ssid": result.wifi.ssid,
                "authentication": result.wifi.authentication,
                "category": result.wifi.category,
                "band": result.wifi.band,
                "platform": result.wifi.platform,
            }
            if result.wifi is not None else None
        ),
        "network_findings": [_finding_json(f) for f in result.network_findings],
        "hosts": [
            {
                "ip": h.ip,
                "mac": h.mac,
                "vendor": h.vendor,
                "hostname": h.hostname,
                "device_type": h.device_type,
                "is_gateway": h.is_gateway,
                "open_ports": [
                    {"port": op.port, "service": op.service, "banner": op.banner}
                    for op in h.open_ports
                ],
                "findings": [_finding_json(f) for f in h.findings],
            }
            for h in result.hosts
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"  JSON results written to {path}")


def _force_utf8_output() -> None:
    """Make stdout/stderr UTF-8 so box-drawing/emoji don't crash on Windows.

    Windows consoles default to a legacy code page (e.g. cp1252) that can't
    encode the report's ●/✓/box characters. Reconfigure to UTF-8 and replace
    anything still unencodable rather than raising.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_output()
    args = build_parser().parse_args(argv)

    if not _confirm_consent(args.yes_i_own_this_network):
        print("Aborted. No scan was performed.")
        return 2

    try:
        result = run_scan(args)
        _maybe_online_cve(result, args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except (RuntimeError, SystemExit) as exc:
        print(f"Error: {exc}")
        return 1

    print(render_console(result, use_color=not args.no_color))

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(result))
        print(f"  HTML report written to {args.html}")
    if args.json:
        _write_json(result, args.json)

    # Exit code reflects worst finding so scripts/CI can react.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
