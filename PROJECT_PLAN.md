# HomeGuard — Project Plan

## Pitch

A free, privacy-first tool that scans your home network and tells you, in plain
English, what's exposed and how to fix it. **No cloud upload, no account, no data
leaves the machine.** Think "Have I Been Pwned," but for your router and smart
devices instead of your email.

## Why this has mass appeal

- Everyone with a router / smart TV / camera / doorbell is a potential user — not
  just security professionals.
- Zero setup cost to try: no signup, no cloud dependency, runs locally.
- Emotionally resonant hook: *"is my baby monitor / camera exposed?"*
- Shareable results ("my network scored a B-") drive organic word of mouth.

## MVP scope (this build)

1. **Discovery** — detect the local subnet, ping-sweep it, read the OS ARP table
   to get IP↔MAC pairs. No root/admin and no raw sockets required.
2. **Port scan** — threaded TCP connect scan of the ports most associated with
   IoT/router compromise (telnet, VNC, UPnP/TR-069, RTSP/CCTV, SMB, FTP, exposed
   HTTP admin panels, ADB, MQTT, …).
3. **Fingerprinting** — banner grab on open ports + MAC vendor lookup to label
   devices ("Hikvision camera", "TP-Link router", "unknown IoT device").
4. **Risk engine** — rules-based scoring per finding, each with a plain-English
   explanation and fix instructions. No jargon dump.
5. **Report** — console summary with an overall network grade (A–F) plus an
   exportable, self-contained HTML report for sharing/saving.

## Explicitly out of scope for MVP (see roadmap)

- Wi-Fi encryption/config auditing (WPA2 vs WPA3, WPS).
- External/WAN exposure testing (needs an outside vantage point).
- Actual credential testing (default-password attempts) — the MVP only *flags*
  that a default-cred-prone service is open; it never attempts a login.
- GUI/packaging into a double-click app.

## Roadmap

### Week 1 — harden the core engine
- Expand the risky-port list and banner-grab fingerprints (more camera/DVR
  brands, more router admin-panel signatures).
- Add a CVE-lookup step: match fingerprinted device/firmware banners against a
  local snapshot of known CVEs for common router/camera models.
- Add a Wi-Fi config check (WPA2 vs WPA3, WPS enabled) per platform.

### Week 2 — trust, safety, and packaging
- Explicit consent screen + `--yes-i-own-this-network` flag pattern. *(shipped in MVP)*
- Package as a single executable per OS (PyInstaller).
- Simple local web UI (Flask, localhost-only).

### Week 3 — distribution and growth loop
- Shareable HTML/image report card sized for social.
- Optional, opt-in external-exposure check via a public API.
- Landing page + install script; submit to r/homelab, r/HomeNetworking, Product Hunt.

### Later
- Scheduled re-scans with diff reports ("a new device joined your network").
- Native GUI (Tauri/Electron) wrapping the same Python engine.
- Mobile companion app for notifications.

## Legal / ethical note

HomeGuard only scans devices on the network it is run from (your own LAN) and
**never attempts authentication**. Scanning networks you don't own or don't have
permission to test is illegal in most jurisdictions. This stays front and center
in the README and the CLI banner.
