# Changelog

All notable changes to IoTpwned are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Multi-subnet / VLAN scanning** — `--cidr` can now be repeated or given a
  comma-separated list to scan several subnets in one run
  (e.g. `--cidr 192.168.1.0/24 --cidr 192.168.20.0/24`), and the web UI's subnet
  box accepts a comma-separated list too. Devices are merged into one report,
  grouped by subnet, with a single overall grade. The report notes that
  MAC/vendor labels come from ARP (Layer-2) and only resolve within each
  device's own subnet, so remote subnets show fewer details — and that this
  machine must be able to route to each subnet for the scan to reach it.

## [0.8.0] - 2026-07-10

### Added
- **Default-password check** (`--cred-check`, opt-in) — actively tests device
  admin panels for well-known default logins (admin/admin, brand-specific factory
  defaults). It's the only check that attempts a login, so it's off by default
  with its own explicit consent gate, is conservative and non-destructive (HTTP
  Basic auth only — a single authenticated GET, never POSTs or changes settings),
  probes only likely admin devices, and stops on the first hit or a lockout
  signal. A working default login is reported as a Critical finding naming the
  credential. Also available as a (clearly labelled) checkbox in the web UI.

### Changed
- Messaging updated throughout (CLI banner, README, landing page, report footer):
  IoTpwned no longer claims it "never attempts a login" unconditionally — that's
  true by default, with the opt-in `--cred-check` as the stated exception.

## [0.7.0] - 2026-07-09

### Added
- **External exposure check** (`--wan-check`, opt-in) — checks what's reachable
  from the internet on your public IP via Shodan's free InternetDB. Consent-gated
  and data-minimised: only the public IP is sent (to a "what's my IP" service and
  Shodan), never LAN details; the public IP is masked in the shareable HTML/JSON.
  Also available as a checkbox in the web UI. Results reflect Shodan's most recent
  scan (may be cached), which the report states plainly.

## [0.6.1] - 2026-07-09

### Fixed
- The prebuilt executables now open the local **web UI** when launched with no
  arguments (e.g. double-clicked), instead of dropping into the terminal CLI.
  Passing any CLI flag still runs the command-line interface. Only the frozen
  binary's default changed; the `iotpwned` pip console script is unchanged.
- **Web UI:** clicking *Scan* no longer left the browser on a blank, seemingly
  broken page while the scan ran. The scan is now submitted via `fetch()` with a
  live "Scanning…" spinner and elapsed timer, and the report renders in place
  when it finishes (with a friendly error if it fails). Falls back to a plain
  form POST when JavaScript is disabled.

## [0.6.0] - 2026-07-09

First tagged release. Prebuilt, self-contained executables for Linux, macOS, and
Windows are attached to the [GitHub Release](https://github.com/jshaw205/IoTpwned/releases/tag/v0.6.0).

### Added
- **Device discovery** — local subnet detection, threaded ping sweep, and ARP
  parsing to list devices with no admin rights or raw sockets.
- **Risky-port scan** — threaded TCP connect scan of the ports tied to IoT/router
  compromise (Telnet, VNC, RDP, ADB, UPnP/TR-069, RTSP/CCTV, SMB, FTP, MQTT, DVR
  panels, and more), with banner grabbing.
- **Device fingerprinting** — banner signatures + MAC-vendor lookup (offline OUI
  fallback) to label devices ("Hikvision camera", "TP-Link router", …).
- **Risk engine & report** — transparent rules-based scoring with an overall A–F
  grade and a plain-English *why it matters* / *how to fix it* per finding.
  Output as a coloured console summary, a self-contained shareable HTML report
  card, or JSON.
- **Offline known-CVE lookup** — matches each fingerprinted device family against
  a curated, built-in snapshot of notorious router/camera CVEs. No network calls.
- **Opt-in online CVE lookup** (`--online-cve`) — consent-gated queries to the
  live NIST NVD database. Data-minimised: only recognised device brand keywords
  are sent — never IPs, MACs, hostnames, or banners.
- **Wi-Fi encryption check** — reads the machine's current Wi-Fi connection from
  the OS (`netsh` / `airport` / `nmcli`) and flags weak encryption (Open / WEP /
  old WPA), nudging toward WPA2/WPA3. Purely local. Skip with `--no-wifi`.
- **Local web UI** (`--web`) — a localhost-only "click Scan, get a report card"
  interface built on the standard library (no extra dependencies). Binds to
  `127.0.0.1`, validates the `Host` header against DNS rebinding, and uses a
  per-session CSRF token.
- **Single-file executables** — PyInstaller packaging (`packaging/build.py`,
  `iotpwned.spec`) producing a self-contained binary per OS.
- **CI build matrix & release automation** — a GitHub Actions matrix builds and
  tests on Linux/macOS/Windows for every push and pull request, and attaches the
  three OS binaries to a GitHub Release on each version tag.
- **Explicit consent gate** — an "only scan networks you own" prompt before every
  scan, with a `--yes-i-own-this-network` flag for non-interactive use. IoTpwned
  never attempts any password or login.

### Security
- The web UI binds to loopback only, validates the `Host` header, and requires a
  per-session token, so no other origin or remote site can drive the scanner.
- The only feature that ever contacts the internet is the opt-in `--online-cve`
  lookup, and it transmits only device brand keywords.

[Unreleased]: https://github.com/jshaw205/IoTpwned/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/jshaw205/IoTpwned/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jshaw205/IoTpwned/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/jshaw205/IoTpwned/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/jshaw205/IoTpwned/releases/tag/v0.6.0
