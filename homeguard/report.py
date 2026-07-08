"""Rendering — console summary and a self-contained, shareable HTML report.

The HTML report embeds all its own CSS so it can be double-clicked, emailed or
screenshotted with no external assets and no network calls (privacy-first).
"""

from __future__ import annotations

import html
from typing import List

from . import __version__
from .models import Finding, Host, ScanResult, Severity

# ---------------------------------------------------------------------------
# Console rendering
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[97;41m",  # white on red
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}
_GRADE_COLOR = {
    "A": "\033[92m",
    "B": "\033[92m",
    "C": "\033[93m",
    "D": "\033[93m",
    "F": "\033[91m",
}


def _c(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{_RESET}" if use_color else text


def render_console(result: ScanResult, use_color: bool = True) -> str:
    lines: List[str] = []
    add = lines.append

    add("")
    add("=" * 64)
    add(f"  HomeGuard report — {result.subnet}")
    add(f"  {len(result.hosts)} device(s) found · scan took "
        f"{result.duration_seconds:.1f}s")
    add("=" * 64)

    grade_color = _GRADE_COLOR.get(result.grade, "")
    add("")
    add(f"  NETWORK GRADE:  {_c(result.grade, grade_color, use_color)}"
        f"   (health score {result.score}/100)")
    add(f"  {_grade_blurb(result.grade)}")
    add("")

    # Severity tally
    tally = _severity_tally(result.all_findings)
    if tally:
        parts = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW):
            if tally.get(sev):
                parts.append(_c(f"{tally[sev]} {sev.label}",
                                _SEVERITY_COLOR[sev], use_color))
        add("  Findings: " + "  ·  ".join(parts))
        add("")

    for host in result.hosts:
        _render_host_console(host, add, use_color)

    add("=" * 64)
    add("  HomeGuard only scanned your own LAN and never tried any password.")
    add("  Fix the Critical and High items first. Re-run after changes.")
    add("=" * 64)
    add("")
    return "\n".join(lines)


def _render_host_console(host: Host, add, use_color: bool) -> None:
    tag = " [gateway]" if host.is_gateway else ""
    header = f"● {host.ip}{tag} — {host.device_type}"
    add(header)
    meta = []
    if host.hostname:
        meta.append(host.hostname)
    if host.vendor:
        meta.append(host.vendor)
    if host.mac:
        meta.append(host.mac)
    if meta:
        add("    " + "  ·  ".join(meta))

    if not host.findings:
        add("    " + _c("No risky services detected. ✓", "\033[92m", use_color))
        add("")
        return

    for f in host.findings:
        badge = _c(f" {f.severity.label.upper()} ",
                   _SEVERITY_COLOR[f.severity], use_color)
        add(f"    {badge} {f.title}")
        add(f"        Why:  {f.why}")
        add(f"        Fix:  {f.fix}")
    add("")


def _grade_blurb(grade: str) -> str:
    return {
        "A": "Looking good — nothing alarming is exposed on your network.",
        "B": "Solid, with a few things worth tightening up.",
        "C": "Some real exposure here — worth spending 20 minutes on the fixes.",
        "D": "Several devices are exposing risky services. Act on these soon.",
        "F": "Serious exposure found. Fix the Critical items today.",
    }.get(grade, "")


def _severity_tally(findings: List[Finding]) -> dict:
    tally: dict = {}
    for f in findings:
        tally[f.severity] = tally.get(f.severity, 0) + 1
    return tally


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_GRADE_HEX = {
    "A": "#1a9850", "B": "#66bd63", "C": "#fdae61",
    "D": "#f46d43", "F": "#d73027",
}
_SEV_HEX = {
    Severity.CRITICAL: "#b2182b",
    Severity.HIGH: "#d73027",
    Severity.MEDIUM: "#fdae61",
    Severity.LOW: "#4575b4",
    Severity.INFO: "#999999",
}


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def render_html(result: ScanResult) -> str:
    grade = result.grade
    grade_hex = _GRADE_HEX.get(grade, "#666")
    tally = _severity_tally(result.all_findings)

    tally_html = "".join(
        f'<span class="pill" style="background:{_SEV_HEX[sev]}">'
        f'{tally[sev]} {sev.label}</span>'
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW)
        if tally.get(sev)
    ) or '<span class="pill" style="background:#1a9850">No risks found</span>'

    hosts_html = "\n".join(_host_html(h) for h in result.hosts)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HomeGuard report — {_e(result.subnet)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0; background: #f5f6f8; color: #1a1a1a; line-height: 1.5;
  }}
  .wrap {{ max-width: 820px; margin: 0 auto; padding: 24px 18px 60px; }}
  .card {{
    background: #fff; border-radius: 14px; padding: 22px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 18px;
  }}
  header.hero {{ text-align: center; }}
  .brand {{ font-weight: 700; letter-spacing: .02em; color: #444; }}
  .grade {{
    display: inline-flex; align-items: center; justify-content: center;
    width: 128px; height: 128px; border-radius: 50%;
    font-size: 68px; font-weight: 800; color: #fff;
    background: {grade_hex}; margin: 10px 0;
  }}
  .score {{ color: #555; font-size: 15px; }}
  .blurb {{ font-size: 17px; margin-top: 8px; }}
  .pills {{ margin-top: 14px; }}
  .pill {{
    display: inline-block; color: #fff; font-size: 12.5px; font-weight: 600;
    padding: 4px 11px; border-radius: 999px; margin: 3px;
  }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: .05em;
        color: #666; margin: 4px 0 14px; }}
  .host {{ border-top: 1px solid #eee; padding: 16px 0; }}
  .host:first-of-type {{ border-top: none; }}
  .host-head {{ display: flex; justify-content: space-between; flex-wrap: wrap;
                gap: 6px; align-items: baseline; }}
  .host-ip {{ font-weight: 700; font-size: 17px; }}
  .host-type {{ color: #333; }}
  .host-meta {{ color: #888; font-size: 13px; margin-top: 2px;
                word-break: break-all; }}
  .clean {{ color: #1a9850; font-weight: 600; margin-top: 8px; }}
  .finding {{ margin-top: 12px; padding-left: 12px;
              border-left: 4px solid #ccc; }}
  .finding .sev {{ font-size: 11px; font-weight: 700; color: #fff;
                   padding: 2px 8px; border-radius: 4px; }}
  .finding .ftitle {{ font-weight: 600; margin-left: 8px; }}
  .finding p {{ margin: 6px 0 0; font-size: 14px; }}
  .finding .fix {{ color: #1a6e2e; }}
  .badge-gw {{ font-size: 11px; background: #4575b4; color:#fff;
               padding: 1px 7px; border-radius: 4px; margin-left: 6px; }}
  footer {{ text-align: center; color: #999; font-size: 12.5px;
            margin-top: 20px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #16181d; color: #e6e6e6; }}
    .card {{ background: #23262d; box-shadow: none; }}
    .host {{ border-color: #33363d; }}
    .host-type {{ color: #cfcfcf; }}
    .finding .fix {{ color: #7ad18f; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header class="card hero">
    <div class="brand">🛡 HomeGuard</div>
    <div class="grade">{_e(grade)}</div>
    <div class="score">Network health score: <strong>{result.score}/100</strong></div>
    <div class="blurb">{_e(_grade_blurb(grade))}</div>
    <div class="pills">{tally_html}</div>
    <div class="host-meta">Subnet {_e(result.subnet)} ·
      {len(result.hosts)} device(s) · scanned in {result.duration_seconds:.1f}s ·
      {_e(result.finished_at)}</div>
  </header>

  <section class="card">
    <h2>Devices &amp; findings</h2>
    {hosts_html}
  </section>

  <footer>
    Generated locally by HomeGuard v{__version__}. No data left this machine.<br>
    Only scan networks you own or have permission to test.
  </footer>
</div>
</body>
</html>
"""


def _host_html(host: Host) -> str:
    gw = '<span class="badge-gw">gateway</span>' if host.is_gateway else ""
    meta_bits = [b for b in (host.hostname, host.vendor, host.mac) if b]
    meta = " · ".join(_e(b) for b in meta_bits)

    if host.findings:
        findings_html = "\n".join(_finding_html(f) for f in host.findings)
    else:
        findings_html = '<div class="clean">No risky services detected ✓</div>'

    return f"""
    <div class="host">
      <div class="host-head">
        <span class="host-ip">{_e(host.ip)}{gw}</span>
        <span class="host-type">{_e(host.device_type)}</span>
      </div>
      <div class="host-meta">{meta}</div>
      {findings_html}
    </div>"""


def _finding_html(f: Finding) -> str:
    color = _SEV_HEX[f.severity]
    return f"""
      <div class="finding" style="border-left-color:{color}">
        <div><span class="sev" style="background:{color}">{_e(f.severity.label.upper())}</span>
          <span class="ftitle">{_e(f.title)}</span></div>
        <p>{_e(f.why)}</p>
        <p class="fix"><strong>Fix:</strong> {_e(f.fix)}</p>
      </div>"""
