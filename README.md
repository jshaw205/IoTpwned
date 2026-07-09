# 🛡 IoTpwned

**A free, privacy-first tool that scans your home network and tells you, in plain
English, what's exposed and how to fix it.**

[![Build & Release](https://github.com/jshaw205/IoTpwned/actions/workflows/build-and-release.yml/badge.svg)](https://github.com/jshaw205/IoTpwned/actions/workflows/build-and-release.yml)

Think *Have I Been Pwned*, but for your router, cameras, and smart devices instead
of your email. No cloud upload, no account, no data leaves your machine.

```
  NETWORK GRADE:  F   (health score 21/100)
  Serious exposure found. Fix the Critical items today.

  Findings: 1 Critical  ·  2 High  ·  1 Medium

● 192.168.1.30 — Hikvision IP camera / DVR
     CRITICAL  Telnet (alt) exposed (port 2323)
        Why:  This is Telnet on an alternate port — the exact target of
              Mirai-family botnets. Unencrypted remote control with default logins.
        Fix:  Disable Telnet in the device settings. If it can't be turned off,
              isolate or replace the device.
```

---

## ⚠️ Only scan networks you own

IoTpwned only scans devices on the network it is run from (**your own LAN**) and
**never attempts any password or login** — it only reports that a risky service is
*open*. Scanning networks you don't own or don't have permission to test is
**illegal in most jurisdictions**. IoTpwned asks you to confirm this before every
scan.

---

## What it does

1. **Discovery** — detects your local subnet, ping-sweeps it, and reads the OS ARP
   table for IP↔MAC pairs. No root/admin and no raw sockets required.
2. **Port scan** — a threaded TCP connect scan of the ports most associated with
   IoT/router compromise (Telnet, VNC, RDP, ADB, UPnP/TR-069, RTSP/CCTV, SMB, FTP,
   MQTT, exposed HTTP admin panels, and known DVR control ports).
3. **Fingerprinting** — banner grabbing + MAC-vendor lookup to label devices
   ("Hikvision camera", "TP-Link router", "unknown IoT device").
4. **Known-CVE lookup** — matches each fingerprinted device family against a local,
   offline snapshot of notorious router/camera CVEs (Hikvision CVE-2021-36260,
   Dahua CVE-2021-33044, the RomPager "Misfortune Cookie", the Mirai-exploited
   TP-Link Archer bug, and more) and tells you to check your firmware. No NVD API
   calls — the snapshot ships with the tool. An **opt-in** online lookup
   (`--online-cve`) can additionally query the live NIST NVD database — see
   *[Online CVE lookup](#online-cve-lookup-opt-in)* below.
5. **Wi-Fi check** — reads your machine's current Wi-Fi connection from the OS and
   flags weak encryption (Open / WEP / old WPA), nudging you toward WPA2/WPA3.
   Purely local — nothing is transmitted. Runs by default; `--no-wifi` to skip.
6. **Risk engine** — transparent, rules-based scoring. Every finding comes with a
   plain-English *why it matters* and *how to fix it* — no jargon dump.
7. **Report** — a console summary with an overall A–F network grade, plus an
   exportable, self-contained HTML report card you can save or share.

## Install

Requires Python 3.9+.

```bash
# from the project directory
pip install -e .

# optional: richer MAC-vendor labels via the offline Wireshark OUI database
pip install -e ".[vendor]"
```

IoTpwned's core runs entirely on the Python standard library, so it works offline
with zero third-party packages. The `vendor` extra only enriches device labelling.

## Usage

```bash
iotpwned                              # auto-detect subnet, scan, print report
iotpwned --cidr 192.168.1.0/24        # scan a specific range
iotpwned --html report.html           # also write a shareable HTML report card
iotpwned --json report.json           # machine-readable output
iotpwned --yes-i-own-this-network     # skip the interactive consent prompt
```

Or without installing:

```bash
python -m iotpwned --cidr 192.168.1.0/24
```

### Web UI

Prefer clicking a button? Launch the local, **localhost-only** web UI:

```bash
iotpwned --web            # opens http://127.0.0.1:8765 in your browser
```

Tick the consent box, hit **Scan my network**, and you get the same report card
in the browser. It binds to `127.0.0.1` only (never the network), validates the
`Host` header against DNS-rebinding, and uses a per-session token so no other
site can drive your scanner. No extra dependencies — it's built on Python's
standard library. `--web-port PORT` and `--no-browser` are available.

### Useful flags

| Flag | Purpose |
|------|---------|
| `--cidr CIDR` | Subnet to scan (default: auto-detect). |
| `--html PATH` | Write a shareable HTML report. |
| `--json PATH` | Write machine-readable JSON. |
| `--timeout SEC` | Per-port TCP connect timeout (default 1.0s). |
| `--no-ping` | Skip the ping sweep; use only the existing ARP cache. |
| `--no-resolve` | Skip reverse-DNS lookups (faster). |
| `--no-wifi` | Skip the local Wi-Fi encryption check. |
| `--ports LIST` | Scan a custom comma-separated port list. |
| `--yes-i-own-this-network` | Confirm authorisation non-interactively. |
| `--web` | Launch the localhost-only web UI instead of the CLI scan. |
| `--web-port PORT` | Port for the web UI (default 8765). |
| `--online-cve` | Opt in to the live NVD CVE lookup (asks for consent). |
| `--yes-online-cve` | Pre-consent to the online lookup non-interactively. |
| `--online-cve-limit N` | Max CVEs per brand from the online lookup (default 5). |
| `--nvd-api-key KEY` | NVD API key for a higher rate limit (or `NVD_API_KEY`). |

## Online CVE lookup (opt-in)

By default IoTpwned is **fully offline** — the only CVE matching it does is against
the snapshot that ships with the tool. If you want deeper, always-current results,
`--online-cve` queries the official **NIST NVD** database
(`services.nvd.nist.gov`). Because this is the one feature that talks to the
internet, it is deliberately constrained:

- **Off by default and consent-gated.** It runs only with `--online-cve`, and a
  separate prompt asks before any request — showing you the exact keywords first.
- **Data minimisation.** Only the *brand keyword* of a recognised device (e.g.
  `Hikvision`) is sent. Never IP addresses, MAC addresses, hostnames, or banners.
  Unknown/generic devices are never looked up, so nothing about them leaves.
- **Additive & de-duplicated.** Online results supplement the offline snapshot;
  a CVE already flagged offline isn't reported twice.
- **Fails safe.** Any network error is ignored per-brand; your offline results
  still stand.

```bash
iotpwned --online-cve                    # prompts for consent, then queries NVD
iotpwned --online-cve --yes-online-cve   # pre-consented (e.g. for scripts)
```

No API key is required; set `NVD_API_KEY` (or `--nvd-api-key`) for a higher rate
limit if you scan many device brands.

## How the grade works

Every finding deducts points from a starting score of 100, weighted by severity
(Critical > High > Medium > Low). The remaining score maps to a letter grade:

| Score | Grade |
|-------|-------|
| 95–100 | A |
| 85–94 | B |
| 70–84 | C |
| 55–69 | D |
| < 55 | F |

## Project layout

```
iotpwned/
  discovery.py     # subnet detect, ping sweep, ARP parsing (no root)
  scanner.py       # threaded TCP connect scan + banner grab
  fingerprint.py   # MAC-vendor lookup + banner signature matching
  data.py          # risky-port catalogue, signatures, OUI fallback table
  cve_data.py      # offline snapshot of known IoT/router CVEs
  cve.py           # match fingerprinted devices against the CVE snapshot
  cve_online.py    # opt-in, consent-gated live NVD API lookup
  wifi.py          # local Wi-Fi encryption check (netsh/airport/nmcli)
  risk.py          # rules-based scoring engine (why + fix per finding)
  report.py        # console + self-contained HTML rendering
  engine.py        # shared scan pipeline used by the CLI and web UI
  webui.py         # localhost-only web UI (stdlib http.server)
  cli.py           # consent gate + pipeline orchestration
tests/             # pytest unit tests for every stage
```

**Extending coverage** (see the roadmap in [PROJECT_PLAN.md](PROJECT_PLAN.md)): add
ports to `RISKY_PORTS`, brand signatures to `BANNER_SIGNATURES`, and MAC prefixes
to `OUI_FALLBACK` — all in [iotpwned/data.py](iotpwned/data.py). Add known
vulnerabilities as `CVERecord` entries in [iotpwned/cve_data.py](iotpwned/cve_data.py).

## Standalone executable

For non-technical users who don't have Python, IoTpwned can be frozen into a
single double-clickable executable with [PyInstaller](https://pyinstaller.org):

```bash
pip install -e ".[build]"
python packaging/build.py --clean
# -> dist/iotpwned  (dist/iotpwned.exe on Windows), a single ~8 MB file
```

The binary is fully self-contained (no Python needed on the target machine) and
still zero-network by default. **PyInstaller can't cross-compile**, so run the
build on each OS you want a binary for — Windows on Windows, macOS on macOS,
Linux on Linux. See [packaging/README.md](packaging/README.md) for details and
the per-OS notes.

### Automated release builds

A GitHub Actions matrix
([`.github/workflows/build-and-release.yml`](.github/workflows/build-and-release.yml))
runs the tests and a PyInstaller build on Linux, macOS, and Windows for every
push and pull request. Pushing a version tag builds all three and attaches them
to a GitHub Release automatically:

```bash
git tag v0.6.0
git push origin v0.6.0     # -> Release with iotpwned-linux-x64, -macos-arm64, -windows-x64.exe
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for the full plan. Highlights:

- **Week 1** — ~~CVE lookup against a local snapshot~~ ✅ *shipped*; ~~Wi-Fi config
  check (WPA2/WPA3)~~ ✅ *shipped*; more device fingerprints.
- **Week 2** — ~~localhost-only web UI~~ ✅ *shipped (stdlib, `--web`)*;
  ~~PyInstaller single-file executables~~ ✅ *shipped (`packaging/`)*.
- **Week 3** — social-sized shareable report card; ~~opt-in external API lookup~~
  ✅ *online NVD CVE lookup shipped*; opt-in external-exposure check; landing page.
- **Later** — scheduled re-scans with diff reports; native GUI; mobile companion.

## License

MIT.
