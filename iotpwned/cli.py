"""Command-line interface for IoTpwned.

    iotpwned                         # auto-detect subnet, scan, print report
    iotpwned --cidr 192.168.1.0/24   # scan a specific range
    iotpwned --html report.html      # also write a shareable HTML report
    iotpwned --yes-i-own-this-network  # skip the interactive consent prompt

Pipeline: discovery -> port scan -> fingerprint -> risk score -> report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__, cve_online, engine, wan, webui
from .discovery import default_subnet
from .models import ScanResult
from .report import render_console, render_html

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
│  By default IoTpwned never tries a login; the default-password │
│  check (--cred-check) is opt-in and asks again before running. │
└────────────────────────────────────────────────────────────────┘
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iotpwned",
        description="Privacy-first home network IoT security scanner.",
        epilog="Only scan networks you own or have permission to test.",
    )
    p.add_argument("--cidr", metavar="CIDR", action="append",
                   help="Subnet to scan, e.g. 192.168.1.0/24 "
                        "(default: auto-detect). Repeat the flag or pass a "
                        "comma-separated list to scan several subnets/VLANs at "
                        "once, e.g. --cidr 192.168.1.0/24 --cidr 192.168.20.0/24 "
                        "(this machine must be able to route to each one).")
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
    p.add_argument("--web", action="store_true",
                   help="Launch the local (localhost-only) web UI instead of "
                        "scanning from the command line.")
    p.add_argument("--web-port", type=int, default=8765, metavar="PORT",
                   help="Port for the web UI (default 8765).")
    p.add_argument("--no-browser", action="store_true",
                   help="With --web, don't auto-open a browser tab.")
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
    p.add_argument("--wan-check", action="store_true",
                   help="Also check what's exposed to the internet on your "
                        "public IP, via Shodan's InternetDB. OFF by default and "
                        "asks for consent first, since it sends your public IP "
                        "to an external service.")
    p.add_argument("--yes-wan-check", action="store_true",
                   help="Pre-consent to the external exposure check (implies "
                        "--wan-check) and skip its interactive prompt.")
    p.add_argument("--public-ip", metavar="IP", default=None,
                   help="Use this public IP for the exposure check instead of "
                        "auto-detecting it (avoids the IP-lookup service).")
    p.add_argument("--cred-check", action="store_true",
                   help="Actively test admin panels for well-known DEFAULT "
                        "passwords (e.g. admin/admin). OFF by default and asks "
                        "for consent — this is the only check that tries a login.")
    p.add_argument("--yes-cred-check", action="store_true",
                   help="Pre-consent to the default-password check (implies "
                        "--cred-check) and skip its interactive prompt.")
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
    added = engine.apply_online_cve(
        result,
        limit=args.online_cve_limit,
        api_key=api_key,
        progress=_progress("NVD lookup"),
    )
    print(f"  Online CVE lookup added {added} finding(s).")


def _confirm_wan_consent(assume_yes: bool) -> bool:
    """Separate consent gate for the external exposure check."""
    print()
    print("  ── External exposure check ───────────────────────────────────")
    print("  This looks up your PUBLIC IP (via api.ipify.org) and checks it")
    print("  against Shodan's InternetDB (internetdb.shodan.io) to see what's")
    print("  reachable from the internet. Only your public IP is sent — no LAN")
    print("  details, device names, or MAC addresses. Results reflect Shodan's")
    print("  most recent scan and may be cached.")
    print("  ──────────────────────────────────────────────────────────────")
    if assume_yes:
        print("  Consent confirmed via --yes-wan-check.\n")
        return True
    if not sys.stdin.isatty():
        print("  Skipping exposure check: no terminal to confirm consent. "
              "Re-run with --yes-wan-check to allow it.\n")
        return False
    try:
        answer = input("  Look up your public IP and query Shodan? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def _maybe_wan_check(result: ScanResult, args: argparse.Namespace) -> None:
    """If enabled and consented, run the external exposure check."""
    if not (args.wan_check or args.yes_wan_check):
        return
    if not _confirm_wan_consent(args.yes_wan_check):
        return

    sys.stderr.write("  Checking external exposure ...\n")
    info = engine.apply_wan_check(result, public_ip=args.public_ip)
    if not info.supported or info.error:
        print(f"  Exposure check: {info.error or 'unavailable'}.")
    elif not info.open_ports and not info.vulns:
        print("  Exposure check: Shodan reports nothing open on your public IP. ✓")
    else:
        print(f"  Exposure check: {len(info.open_ports)} port(s) reachable from "
              f"the internet.")


def _confirm_cred_consent(assume_yes: bool) -> bool:
    """Strong, separate consent gate for the active default-password check."""
    print()
    print("  ══ Default-password check ════════════════════════════════════")
    print("  WARNING: this ACTIVELY TRIES to log in to admin panels on your")
    print("  network using well-known DEFAULT passwords (e.g. admin/admin).")
    print("  Run it ONLY on devices you own. It makes a few login attempts per")
    print("  device and could, in rare cases, briefly lock an admin account.")
    print("  It never changes any settings — it only reports what it finds.")
    print("  ══════════════════════════════════════════════════════════════")
    if assume_yes:
        print("  Consent confirmed via --yes-cred-check.\n")
        return True
    if not sys.stdin.isatty():
        print("  Skipping default-password check: no terminal to confirm "
              "consent. Re-run with --yes-cred-check to allow it.\n")
        return False
    try:
        answer = input("  Try default passwords on your own admin panels? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def _maybe_cred_check(result: ScanResult, args: argparse.Namespace) -> None:
    """If enabled and consented, actively test admin panels for default logins."""
    if not (args.cred_check or args.yes_cred_check):
        return
    if not _confirm_cred_consent(args.yes_cred_check):
        return

    sys.stderr.write("  Testing admin panels for default passwords ...\n")
    tested, weak = engine.apply_cred_check(result)
    if tested == 0:
        print("  Default-password check: no testable admin panels found.")
    elif weak == 0:
        print(f"  Default-password check: {tested} admin panel(s) tested, none "
              f"on a default password. ✓")
    else:
        print(f"  Default-password check: {weak} device(s) on a DEFAULT password.")


def _parse_cidrs(values: Optional[List[str]]) -> Optional[List[str]]:
    """Flatten repeated/comma-separated ``--cidr`` values into an ordered list.

    Accepts the raw argparse ``append`` list, splits each entry on commas (and
    whitespace), trims blanks, and de-duplicates while preserving order.
    """
    if not values:
        return None
    out: List[str] = []
    seen = set()
    for value in values:
        for part in value.replace(" ", ",").split(","):
            part = part.strip()
            if part and part not in seen:
                seen.add(part)
                out.append(part)
    return out or None


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

    cidrs = _parse_cidrs(args.cidr)
    if not cidrs:
        auto = default_subnet()
        if not auto:
            raise SystemExit(
                "Could not auto-detect your subnet. Pass one with "
                "--cidr, e.g. --cidr 192.168.1.0/24"
            )
        cidrs = [auto]

    if len(cidrs) == 1:
        print(f"\nScanning {cidrs[0]} ...\n")
    else:
        print(f"\nScanning {len(cidrs)} subnets: {', '.join(cidrs)} ...")
        print("(Each subnet must be reachable from this machine — see the note "
              "in the report about VLANs.)\n")

    def _subnet_start(cidr, idx, total):
        if total > 1:
            print(f"\n[{cidr}]  (subnet {idx + 1} of {total})")

    def _found(hosts):
        print(f"  Found {len(hosts)} device(s). Scanning ports ...")

    return engine.run_pipeline(
        cidrs=cidrs,
        ports=ports,
        timeout=args.timeout,
        ping_timeout=args.ping_timeout,
        do_ping=not args.no_ping,
        resolve=not args.no_resolve,
        do_wifi=not args.no_wifi,
        on_subnet_start=_subnet_start,
        on_discovery_progress=_progress("Pinging"),
        on_hosts_discovered=_found,
        on_scan_progress=_progress("Port-scanning"),
    )


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
        "subnets": result.subnets or [result.subnet],
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
        "wan": (
            {
                "checked": result.wan.checked,
                "supported": result.wan.supported,
                # Public IP is masked in saved output for privacy.
                "public_ip_masked": wan.mask_ip(result.wan.public_ip),
                "open_ports": result.wan.open_ports,
                "vulns": result.wan.vulns,
                "source": result.wan.source,
                "error": result.wan.error,
            }
            if result.wan is not None else None
        ),
        "network_findings": [_finding_json(f) for f in result.network_findings],
        "hosts": [
            {
                "ip": h.ip,
                "subnet": h.subnet,
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

    if args.web:
        try:
            webui.serve(port=args.web_port, open_browser=not args.no_browser)
        except KeyboardInterrupt:
            print("\nWeb UI stopped.")
        return 0

    if not _confirm_consent(args.yes_i_own_this_network):
        print("Aborted. No scan was performed.")
        return 2

    try:
        result = run_scan(args)
        _maybe_online_cve(result, args)
        _maybe_wan_check(result, args)
        _maybe_cred_check(result, args)
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
