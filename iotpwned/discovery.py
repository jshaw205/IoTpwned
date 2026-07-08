"""Host discovery — find the devices on the local network.

Design constraints (from the plan): **no root/admin and no raw sockets.** We
achieve this by:

1. Finding our own IP with a UDP "connect" trick (no packet is actually sent).
2. Ping-sweeping the subnet with the OS ``ping`` command (threaded). This both
   tells us which hosts are alive *and* populates the OS ARP cache.
3. Reading IP<->MAC pairs back out of the ARP cache via ``arp -a``.

All three work as an unprivileged user on Windows, macOS and Linux.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from .models import Host

_IS_WINDOWS = platform.system().lower().startswith("win")

# arp -a lines look like:
#   Windows:  "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
#   POSIX:    "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
_ARP_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"
    r"(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
)


def get_primary_ip() -> Optional[str]:
    """Return this machine's primary LAN IPv4 address, or None.

    Uses a UDP socket "connected" to a public address. No traffic is sent —
    the OS just picks the outbound interface — so this works offline and needs
    no privileges.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    finally:
        s.close()

    # Fallback: resolve the hostname.
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return None


def default_subnet(prefix: int = 24) -> Optional[str]:
    """Best-effort local subnet as a CIDR string, assuming a ``/prefix`` mask.

    Home networks are almost always /24, so we default to that. Users can
    override with an explicit CIDR on the command line.
    """
    ip = get_primary_ip()
    if not ip:
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None
    return str(net)


def _ping_cmd(ip: str, timeout_ms: int) -> List[str]:
    if _IS_WINDOWS:
        # -n 1 (one echo), -w timeout in ms.
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    # POSIX: -c 1 (one echo), -W timeout in seconds (round up to >=1).
    timeout_s = max(1, round(timeout_ms / 1000))
    return ["ping", "-c", "1", "-W", str(timeout_s), ip]


def ping_host(ip: str, timeout_ms: int = 700) -> bool:
    """Return True if ``ip`` answers a single ICMP echo."""
    try:
        proc = subprocess.run(
            _ping_cmd(ip, timeout_ms),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(2, timeout_ms / 1000 + 1),
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_sweep(
    cidr: str,
    timeout_ms: int = 700,
    workers: int = 64,
    progress=None,
) -> List[str]:
    """Ping every usable host in ``cidr`` concurrently; return the live ones.

    Also has the side effect of populating the OS ARP cache, which
    :func:`read_arp_table` then reads for MAC addresses.
    """
    from concurrent.futures import as_completed

    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]
    alive: List[str] = []
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping_host, ip, timeout_ms): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            done += 1
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass
            if progress:
                progress(done, len(hosts), ip)

    alive.sort(key=lambda s: tuple(int(o) for o in s.split(".")))
    return alive


def read_arp_table() -> Dict[str, str]:
    """Parse the OS ARP cache into an ``{ip: mac}`` map (MACs normalised)."""
    try:
        out = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            text=True,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return {}

    table: Dict[str, str] = {}
    for line in out.splitlines():
        m = _ARP_RE.search(line)
        if not m:
            continue
        mac = normalise_mac(m.group("mac"))
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            continue
        table[m.group("ip")] = mac
    return table


def normalise_mac(mac: str) -> str:
    """Return a MAC as upper-case colon-separated ``AA:BB:CC:DD:EE:FF``."""
    hexonly = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(hexonly) != 12:
        return mac.upper()
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


def resolve_hostname(ip: str) -> Optional[str]:
    """Best-effort reverse-DNS lookup; returns None if it fails quickly."""
    try:
        socket.setdefaulttimeout(1.0)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def discover_hosts(
    cidr: Optional[str] = None,
    timeout_ms: int = 700,
    do_ping: bool = True,
    resolve_names: bool = True,
    progress=None,
) -> List[Host]:
    """Discover live hosts on ``cidr`` (or the auto-detected subnet).

    Returns :class:`Host` objects populated with ip / mac / hostname and the
    gateway flag. Port scanning and fingerprinting happen in later stages.
    """
    if cidr is None:
        cidr = default_subnet()
    if cidr is None:
        raise RuntimeError(
            "Could not determine the local subnet automatically. "
            "Pass one explicitly, e.g. --cidr 192.168.1.0/24"
        )

    gateway_ip = _guess_gateway(cidr)

    alive: List[str] = []
    if do_ping:
        alive = ping_sweep(cidr, timeout_ms=timeout_ms, progress=progress)

    arp = read_arp_table()

    # Union of ping-alive hosts and anything already in the ARP cache that
    # falls within the target subnet (catches devices that ignore ping).
    network = ipaddress.ip_network(cidr, strict=False)
    ip_set = set(alive)
    for ip in arp:
        try:
            if ipaddress.ip_address(ip) in network:
                ip_set.add(ip)
        except ValueError:
            continue

    my_ip = get_primary_ip()

    hosts: List[Host] = []
    for ip in sorted(ip_set, key=lambda s: tuple(int(o) for o in s.split("."))):
        host = Host(ip=ip, mac=arp.get(ip))
        host.is_gateway = ip == gateway_ip
        if resolve_names:
            host.hostname = resolve_hostname(ip)
        if ip == my_ip:
            host.hostname = host.hostname or "This computer"
        hosts.append(host)

    return hosts


def _guess_gateway(cidr: str) -> Optional[str]:
    """Guess the gateway IP (usually the .1 of the subnet)."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network.network_address + 1)
    except ValueError:
        return None
