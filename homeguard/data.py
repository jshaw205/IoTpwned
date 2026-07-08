"""Static knowledge base for HomeGuard.

Three tables live here:

* ``RISKY_PORTS``    — the TCP ports HomeGuard scans, each tagged with the
                       service, a default severity, and plain-English why/fix
                       text used by the risk engine.
* ``BANNER_SIGNATURES`` — regexes matched against grabbed banners to label a
                       device (camera / DVR / router brands, admin panels).
* ``OUI_FALLBACK``  — a small offline MAC-prefix -> vendor table so vendor
                       labelling works even without the optional
                       ``mac-vendor-lookup`` package installed.

Editing these tables is how you extend coverage (see roadmap: "expand the
risky-port list and banner-grab fingerprints").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .models import Severity


@dataclass(frozen=True)
class PortSpec:
    port: int
    service: str
    severity: Severity
    category: str
    why: str
    fix: str
    # Some services almost never *should* be reachable and are classic
    # default-credential / botnet targets. Flag those a notch louder.
    default_cred_prone: bool = False


# ---------------------------------------------------------------------------
# Risky port catalogue
# ---------------------------------------------------------------------------
# Ports are chosen for their association with IoT/router compromise rather than
# for completeness. SSDP/UPnP discovery itself is UDP 1900 (not TCP-scannable),
# so we watch the TCP control/HTTP ports UPnP stacks expose instead.

RISKY_PORTS: List[PortSpec] = [
    PortSpec(
        21, "FTP", Severity.HIGH, "file-transfer",
        "FTP sends usernames and passwords in clear text and is a common way "
        "cheap cameras and NAS boxes leak files. Many ship with a default "
        "login that never gets changed.",
        "Turn FTP off if you don't use it. If you need file transfer, use SFTP "
        "or a modern cloud/NAS app instead, and change any default password.",
        default_cred_prone=True,
    ),
    PortSpec(
        22, "SSH", Severity.LOW, "remote-admin",
        "SSH is a secure remote-login service, but on a home device it usually "
        "means remote administration is switched on — an extra door into the "
        "device if it uses a weak or default password.",
        "If you don't knowingly use SSH on this device, disable it. If you do, "
        "make sure it uses a strong password or a key, not the factory default.",
    ),
    PortSpec(
        23, "Telnet", Severity.CRITICAL, "remote-admin",
        "Telnet is remote control with NO encryption and is THE service the "
        "Mirai botnet used to hijack millions of cameras and routers via "
        "default passwords. If this is open, treat the device as at risk.",
        "Disable Telnet immediately in the device's settings. If there's no "
        "option to turn it off, the device is unsafe to expose — consider "
        "replacing it or isolating it on a guest network.",
        default_cred_prone=True,
    ),
    PortSpec(
        2323, "Telnet (alt)", Severity.CRITICAL, "remote-admin",
        "This is Telnet on an alternate port — the exact target of Mirai-family "
        "botnets that scan for it. Unencrypted remote control with default "
        "logins.",
        "Disable Telnet in the device settings. If it can't be turned off, "
        "isolate or replace the device.",
        default_cred_prone=True,
    ),
    PortSpec(
        69, "TFTP", Severity.MEDIUM, "file-transfer",
        "TFTP is a password-free file service often left on by routers and IP "
        "phones. It can leak or overwrite firmware and config files.",
        "Disable TFTP unless a device on your network specifically needs it.",
    ),
    PortSpec(
        139, "NetBIOS/SMB", Severity.MEDIUM, "file-sharing",
        "Windows file sharing (older NetBIOS variant). If a device is exposing "
        "it, shared folders may be reachable by anything on the network.",
        "Turn off file/printer sharing if you don't use it, and never expose "
        "SMB to the internet.",
    ),
    PortSpec(
        445, "SMB", Severity.HIGH, "file-sharing",
        "Windows/NAS file sharing. SMB has been at the centre of major worms "
        "(WannaCry, EternalBlue). An exposed, unpatched SMB share is a serious "
        "risk.",
        "Keep the device updated, require a password on shares, and make sure "
        "SMB is never reachable from the internet.",
    ),
    PortSpec(
        554, "RTSP", Severity.HIGH, "camera",
        "RTSP is the live video-streaming protocol used by IP cameras. Many "
        "cameras stream with no password, meaning anyone on the network (or "
        "internet, if port-forwarded) can watch the feed.",
        "Set a strong password on the camera, disable anonymous/unauthenticated "
        "streaming, and never port-forward RTSP to the internet.",
        default_cred_prone=True,
    ),
    PortSpec(
        8554, "RTSP (alt)", Severity.HIGH, "camera",
        "Alternate-port RTSP video stream from an IP camera — same exposure as "
        "standard RTSP: feeds are often viewable without a password.",
        "Require a password for streaming and keep RTSP off the internet.",
        default_cred_prone=True,
    ),
    PortSpec(
        1883, "MQTT", Severity.MEDIUM, "iot-messaging",
        "MQTT is the messaging bus many smart-home hubs use. Unsecured, it can "
        "expose or accept device commands (unlock, arm/disarm, sensor data) "
        "with no authentication.",
        "Enable authentication and TLS on your MQTT broker, or firewall it so "
        "only your hub can reach it.",
    ),
    PortSpec(
        5000, "UPnP (HTTP)", Severity.MEDIUM, "upnp",
        "This is a UPnP control/HTTP endpoint. UPnP lets devices open holes in "
        "your router automatically and has a long history of exploitable bugs.",
        "Disable UPnP on your router unless a specific app needs it, and keep "
        "device firmware up to date.",
    ),
    PortSpec(
        1900, "UPnP SSDP", Severity.MEDIUM, "upnp",
        "UPnP discovery service. Exposed UPnP has repeatedly let attackers "
        "reconfigure routers and reflect denial-of-service attacks.",
        "Turn off UPnP on the router if you don't rely on it, and update "
        "firmware.",
    ),
    PortSpec(
        3389, "RDP", Severity.HIGH, "remote-admin",
        "Remote Desktop lets someone control this machine's screen. Exposed RDP "
        "with a weak password is one of the most common ways computers get "
        "ransomware.",
        "Disable Remote Desktop if you don't use it. If you do, require a "
        "strong password + network-level authentication, and never expose it to "
        "the internet.",
        default_cred_prone=True,
    ),
    PortSpec(
        5555, "ADB (Android)", Severity.HIGH, "remote-admin",
        "Android Debug Bridge over the network. If open, anyone on the network "
        "can install apps or run commands on the device with no password — a "
        "known way Android TV boxes get hijacked for crypto-mining.",
        "Disable network/wireless ADB in the device's Developer Options.",
        default_cred_prone=True,
    ),
    PortSpec(
        5900, "VNC", Severity.HIGH, "remote-admin",
        "VNC shares the device's screen and mouse. Many VNC servers allow "
        "connection with no password at all.",
        "Disable VNC if unused; otherwise set a strong password and keep it off "
        "the internet.",
        default_cred_prone=True,
    ),
    PortSpec(
        7547, "TR-069 (CWMP)", Severity.HIGH, "router-mgmt",
        "TR-069 is the remote-management port ISPs use to configure routers. "
        "Bugs here (e.g. the 'Misfortune Cookie' era) let attackers take over "
        "the router entirely.",
        "You usually can't disable this if your ISP manages the router, so keep "
        "firmware updated and consider using your own router in bridge mode.",
    ),
    PortSpec(
        8080, "HTTP admin (alt)", Severity.MEDIUM, "admin-panel",
        "A web admin panel on an alternate port. Router/camera admin pages here "
        "frequently ship with default logins like admin/admin.",
        "Open the page, change any default username/password, and disable "
        "remote (internet-side) admin access.",
        default_cred_prone=True,
    ),
    PortSpec(
        81, "HTTP (camera)", Severity.MEDIUM, "camera",
        "Port 81 web server — very commonly an IP-camera admin/preview page.",
        "Set a strong camera password and make sure the page isn't reachable "
        "from the internet.",
        default_cred_prone=True,
    ),
    PortSpec(
        8443, "HTTPS admin (alt)", Severity.LOW, "admin-panel",
        "An HTTPS admin panel on an alternate port. Encrypted, but still an "
        "administration login that may use default credentials.",
        "Change default credentials and disable remote admin access.",
        default_cred_prone=True,
    ),
    PortSpec(
        37777, "Dahua DVR", Severity.HIGH, "camera",
        "This is the Dahua camera/DVR control port. Dahua devices have had "
        "several authentication-bypass bugs that expose live video and "
        "credentials.",
        "Update the device firmware, change the default password, and keep it "
        "off the internet.",
        default_cred_prone=True,
    ),
    PortSpec(
        34567, "Xiongmai DVR", Severity.HIGH, "camera",
        "Control port for Xiongmai-based DVRs/cameras (sold under many brands) — "
        "these were heavily abused by the Mirai botnet and have hard-coded "
        "backdoor accounts.",
        "These devices are hard to secure; update firmware if possible and "
        "isolate them on a separate network, or replace them.",
        default_cred_prone=True,
    ),
    PortSpec(
        49152, "UPnP (SOAP)", Severity.MEDIUM, "upnp",
        "A UPnP SOAP control endpoint. This range has hosted serious router "
        "vulnerabilities that expose admin functions without a login.",
        "Disable UPnP on the router if you can, and update firmware.",
    ),
    PortSpec(
        32764, "Router backdoor", Severity.CRITICAL, "router-mgmt",
        "Port 32764 is a notorious hidden backdoor found in several router "
        "brands that grants full admin control with no password.",
        "Update the router firmware immediately; if no fix exists, replace the "
        "router. This should never be open.",
        default_cred_prone=True,
    ),
]

# Ports scanned by default (all of the above minus the UDP-only SSDP entry,
# which a TCP connect scan cannot detect).
DEFAULT_SCAN_PORTS: List[int] = [p.port for p in RISKY_PORTS if p.port != 1900]

PORT_SPECS: Dict[int, PortSpec] = {p.port: p for p in RISKY_PORTS}


# ---------------------------------------------------------------------------
# Banner / device fingerprint signatures
# ---------------------------------------------------------------------------
# Each entry: (case-insensitive regex, device label). First match wins.
BANNER_SIGNATURES: List[tuple] = [
    (r"hikvision|dvrdvs|dnvrs|app-webs", "Hikvision IP camera / DVR"),
    (r"dahua|webs\b.*dahua|dh-", "Dahua IP camera / DVR"),
    (r"uc-httpd", "Budget IP camera (Xiongmai/uc-httpd)"),
    (r"goahead-webs|goahead", "IP camera (GoAhead web server)"),
    (r"boa/0\.9|\bboa\b", "Embedded device (Boa web server)"),
    (r"rompager", "Router (RomPager — check for known CVEs)"),
    (r"mini_httpd", "Router/camera (mini_httpd)"),
    (r"tp-link|tplink|archer", "TP-Link router"),
    (r"netgear|r7000|orbi", "Netgear router"),
    (r"asuswrt|asus", "ASUS router"),
    (r"dd-wrt", "Router (DD-WRT firmware)"),
    (r"openwrt|luci", "Router (OpenWrt firmware)"),
    (r"routeros|mikrotik", "MikroTik router"),
    (r"ubiquiti|unifi|edgeos", "Ubiquiti network device"),
    (r"synology|diskstation", "Synology NAS"),
    (r"qnap", "QNAP NAS"),
    (r"axis", "Axis IP camera"),
    (r"reolink", "Reolink IP camera"),
    (r"wyze", "Wyze smart camera"),
    (r"roku", "Roku streaming device"),
    (r"sonos", "Sonos speaker"),
    (r"printer|jetdirect|cups|ipp", "Network printer"),
    (r"rtsp/1\.0", "IP camera (RTSP video stream)"),
    (r"vnc|rfb 00", "Device with VNC screen sharing"),
    (r"microsoft-iis|windows", "Windows machine"),
    (r"openssh", "Computer/server (SSH)"),
    (r"lighttpd|nginx|apache", "Web server / admin panel"),
]

# Category -> friendly device type, used when a port strongly implies a class of
# device but the banner didn't reveal a brand.
CATEGORY_DEVICE_HINT: Dict[str, str] = {
    "camera": "IP camera / DVR",
    "router-mgmt": "Router / gateway",
    "upnp": "Router / gateway",
    "admin-panel": "Device with a web admin panel",
    "iot-messaging": "Smart-home hub",
    "file-sharing": "File-sharing device / NAS",
}


# ---------------------------------------------------------------------------
# Fallback OUI (MAC prefix -> vendor) table
# ---------------------------------------------------------------------------
# Used when the optional `mac-vendor-lookup` package isn't installed. Prefixes
# are the first three octets, upper-case, colon-separated. This is intentionally
# small — just enough to label the most common home-IoT gear offline.
OUI_FALLBACK: Dict[str, str] = {
    "44:19:B6": "Hangzhou Hikvision",
    "C4:2F:90": "Hangzhou Hikvision",
    "BC:AD:28": "Hangzhou Hikvision",
    "4C:BD:8F": "Zhejiang Dahua",
    "3C:EF:8C": "Zhejiang Dahua",
    "50:C7:BF": "TP-Link",
    "AC:84:C6": "TP-Link",
    "C0:06:C3": "TP-Link",
    "A4:2B:B0": "Netgear",
    "9C:3D:CF": "Netgear",
    "AC:9E:17": "ASUSTek",
    "2C:56:DC": "ASUSTek",
    "FC:EC:DA": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "00:11:32": "Synology",
    "24:5E:BE": "QNAP",
    "00:40:8C": "Axis Communications",
    "EC:71:DB": "Reolink",
    "2C:AA:8E": "Wyze Labs",
    "B0:4A:39": "Roku",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "FC:65:DE": "Amazon Technologies",
    "68:37:E9": "Amazon (Echo/Ring)",
    "F0:EF:86": "Google Nest",
    "18:B4:30": "Google Nest",
    "64:16:66": "Nest Labs",
    "D8:6C:63": "Google",
}
