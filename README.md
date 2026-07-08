# 🛡 IoTpwned

**A free, privacy-first tool that scans your home network and tells you, in plain
English, what's exposed and how to fix it.**

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
4. **Risk engine** — transparent, rules-based scoring. Every finding comes with a
   plain-English *why it matters* and *how to fix it* — no jargon dump.
5. **Report** — a console summary with an overall A–F network grade, plus an
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

### Useful flags

| Flag | Purpose |
|------|---------|
| `--cidr CIDR` | Subnet to scan (default: auto-detect). |
| `--html PATH` | Write a shareable HTML report. |
| `--json PATH` | Write machine-readable JSON. |
| `--timeout SEC` | Per-port TCP connect timeout (default 1.0s). |
| `--no-ping` | Skip the ping sweep; use only the existing ARP cache. |
| `--no-resolve` | Skip reverse-DNS lookups (faster). |
| `--ports LIST` | Scan a custom comma-separated port list. |
| `--yes-i-own-this-network` | Confirm authorisation non-interactively. |

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
  risk.py          # rules-based scoring engine (why + fix per finding)
  report.py        # console + self-contained HTML rendering
  cli.py           # consent gate + pipeline orchestration
tests/             # pytest unit tests for every stage
```

**Extending coverage** (see the roadmap in [PROJECT_PLAN.md](PROJECT_PLAN.md)): add
ports to `RISKY_PORTS`, brand signatures to `BANNER_SIGNATURES`, and MAC prefixes
to `OUI_FALLBACK` — all in [iotpwned/data.py](iotpwned/data.py).

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for the full plan. Highlights:

- **Week 1** — CVE lookup against a local snapshot; Wi-Fi config check (WPA2/WPA3,
  WPS); more device fingerprints.
- **Week 2** — PyInstaller single-file executables; a localhost-only Flask web UI.
- **Week 3** — social-sized shareable report card; opt-in external-exposure check;
  landing page.
- **Later** — scheduled re-scans with diff reports; native GUI; mobile companion.

## License

MIT.
