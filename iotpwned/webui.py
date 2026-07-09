"""A tiny, localhost-only web UI: click Scan, get the report card.

Built on the Python standard library only (``http.server``) so IoTpwned keeps
its zero-dependency install. Security posture for a tool that runs a network
scan on request:

* **Binds to 127.0.0.1 only** — never reachable from the network.
* **Validates the Host header** — blocks DNS-rebinding attempts from a remote
  site pointing a hostname at localhost.
* **Per-process CSRF token** — the scan form carries a token another origin
  can't read, so a random webpage can't drive your scanner.
* **Explicit consent checkbox** — mirrors the CLI's "only scan networks you own"
  gate; the online CVE lookup is a separate, unchecked-by-default opt-in.
"""

from __future__ import annotations

import html
import secrets
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional, Tuple

from . import __version__, engine
from .models import ScanResult
from .report import render_html

ScanFn = Callable[[Dict[str, str]], ScanResult]


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def build_index(token: str, error: Optional[str] = None) -> str:
    err = (f'<div class="err">{html.escape(error)}</div>') if error else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IoTpwned</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0; background: #f5f6f8; color: #1a1a1a; }}
  .wrap {{ max-width: 640px; margin: 0 auto; padding: 40px 18px; }}
  .card {{ background: #fff; border-radius: 14px; padding: 26px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  h1 {{ margin: 0 0 4px; font-size: 26px; }}
  .sub {{ color: #666; margin-bottom: 20px; }}
  .notice {{ background: #fff8e6; border: 1px solid #f0d98c; border-radius: 10px;
    padding: 12px 14px; font-size: 14px; margin-bottom: 18px; }}
  label {{ display: block; font-size: 14px; margin: 14px 0 4px; font-weight: 600; }}
  input[type=text] {{ width: 100%; padding: 9px 11px; border: 1px solid #ccc;
    border-radius: 8px; font-size: 15px; }}
  .check {{ display: flex; gap: 9px; align-items: flex-start; margin: 16px 0;
    font-weight: 400; font-size: 14px; }}
  .check input {{ margin-top: 3px; }}
  .hint {{ color: #777; font-size: 12.5px; margin-top: 2px; }}
  button {{ margin-top: 20px; width: 100%; padding: 13px; font-size: 16px;
    font-weight: 700; color: #fff; background: #1a6e2e; border: none;
    border-radius: 10px; cursor: pointer; }}
  button:disabled {{ background: #9bbfa5; cursor: not-allowed; }}
  .err {{ background: #fdecea; border: 1px solid #f5b5ae; color: #a12; padding: 10px 12px;
    border-radius: 8px; margin-bottom: 16px; font-size: 14px; }}
  .foot {{ color: #999; font-size: 12.5px; margin-top: 18px; text-align: center; }}
  #spin {{ display: none; margin-top: 18px; text-align: center; color: #555; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #16181d; color: #e6e6e6; }}
    .card {{ background: #23262d; box-shadow: none; }}
    input[type=text] {{ background:#16181d; color:#e6e6e6; border-color:#3a3d44; }}
    .notice {{ background:#2b2716; border-color:#5c5222; }}
  }}
</style></head><body>
<div class="wrap"><div class="card">
  <h1>🛡 IoTpwned</h1>
  <div class="sub">Scan your home network and get a plain-English report card.</div>
  {err}
  <div class="notice"><strong>Only scan networks you own</strong> or have
    permission to test. Everything runs locally on this machine; nothing is
    uploaded (unless you opt in to the online CVE lookup below).</div>
  <form method="POST" action="/scan" id="f">
    <input type="hidden" name="token" value="{token}">
    <label for="cidr">Subnet to scan (optional)</label>
    <input type="text" id="cidr" name="cidr" placeholder="auto-detect, e.g. 192.168.1.0/24">
    <div class="hint">Leave blank to auto-detect your local subnet.</div>
    <label class="check"><input type="checkbox" name="consent" value="on">
      <span>I own or have permission to scan this network.</span></label>
    <label class="check"><input type="checkbox" name="online_cve" value="on">
      <span>Also look up known CVEs online (NIST NVD). This sends detected device
      <em>brand names</em> — never IPs, MACs, or banners — over the internet.</span></label>
    <button type="submit" id="go">Scan my network</button>
    <div id="spin">Scanning… this can take up to a minute. Please wait.</div>
  </form>
  <div class="foot">IoTpwned v{__version__} · running locally on 127.0.0.1 ·
    only you can reach this page.</div>
</div></div>
<script>
  document.getElementById('f').addEventListener('submit', function() {{
    document.getElementById('go').disabled = true;
    document.getElementById('go').textContent = 'Scanning…';
    document.getElementById('spin').style.display = 'block';
  }});
</script>
</body></html>"""


def _results_page(result: ScanResult) -> str:
    report = render_html(result)
    back = ('<div style="max-width:820px;margin:0 auto;padding:14px 18px 0">'
            '<a href="/" style="font-size:14px">← Run another scan</a></div>')
    # Inject the back link just inside the report's container.
    return report.replace('<div class="wrap">', back + '<div class="wrap">', 1)


# ---------------------------------------------------------------------------
# Request logic (pure, testable — no sockets)
# ---------------------------------------------------------------------------

def is_local_host(host_header: str) -> bool:
    """True only if the Host header points at loopback (blocks DNS rebinding)."""
    if not host_header:
        return False
    host = host_header.rsplit(":", 1)[0].strip().lower()
    host = host.strip("[]")  # IPv6 literal brackets
    return host in ("127.0.0.1", "localhost", "::1")


def parse_form(body: bytes) -> Dict[str, str]:
    parsed = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
    return {k: v[0] for k, v in parsed.items()}


def process_get(path: str, token: str) -> Tuple[int, str, bytes]:
    if path == "/favicon.ico":
        return 204, "text/plain", b""
    if path in ("/", "/index.html"):
        return 200, "text/html; charset=utf-8", build_index(token).encode("utf-8")
    return 404, "text/plain; charset=utf-8", b"Not found"


def process_post(
    path: str,
    host_header: str,
    body: bytes,
    token: str,
    scan_fn: ScanFn,
) -> Tuple[int, str, bytes]:
    if path != "/scan":
        return 404, "text/plain; charset=utf-8", b"Not found"
    if not is_local_host(host_header):
        return 403, "text/plain; charset=utf-8", b"Forbidden (non-local host)"

    form = parse_form(body)
    if form.get("token") != token:
        return 403, "text/plain; charset=utf-8", b"Forbidden (bad token)"

    if form.get("consent") != "on":
        page = build_index(
            token, error="Please confirm you own or may scan this network."
        )
        return 400, "text/html; charset=utf-8", page.encode("utf-8")

    try:
        result = scan_fn(form)
    except RuntimeError as exc:
        page = build_index(token, error=str(exc))
        return 400, "text/html; charset=utf-8", page.encode("utf-8")

    return 200, "text/html; charset=utf-8", _results_page(result).encode("utf-8")


def default_scan_fn(form: Dict[str, str]) -> ScanResult:
    """Run the real scan from submitted form values."""
    cidr = (form.get("cidr") or "").strip() or None
    result = engine.run_pipeline(cidr=cidr)
    if form.get("online_cve") == "on":
        engine.apply_online_cve(result)
    return result


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def _make_handler(token: str, scan_fn: ScanFn):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"IoTpwned/{__version__}"

        def _send(self, status: int, ctype: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            status, ctype, body = process_get(self.path, token)
            self._send(status, ctype, body)

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            host = self.headers.get("Host", "")
            status, ctype, out = process_post(self.path, host, body, token, scan_fn)
            self._send(status, ctype, out)

        def log_message(self, *args):  # keep the console quiet
            pass

    return Handler


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
    scan_fn: Optional[ScanFn] = None,
) -> None:
    """Run the localhost web UI until interrupted (Ctrl-C)."""
    token = secrets.token_urlsafe(24)
    handler = _make_handler(token, scan_fn or default_scan_fn)
    httpd = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/"
    print(f"IoTpwned web UI running at {url}")
    print("Only reachable from this machine. Press Ctrl-C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
