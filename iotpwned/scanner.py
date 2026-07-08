"""TCP port scanning and banner grabbing.

A plain threaded ``connect()`` scan — no raw sockets, no privileges. We only
probe the curated IoT/router-risk ports from :mod:`iotpwned.data`, and we grab
a short banner from anything that answers so the fingerprinter can identify it.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .data import DEFAULT_SCAN_PORTS, PORT_SPECS
from .models import Host, OpenPort

# Ports where the server expects the client to speak first. For these we send a
# minimal, harmless request to coax a banner out. We NEVER send credentials.
_HTTP_PORTS = {80, 81, 88, 443, 8080, 8443, 8000, 8888, 5000}


def _probe_for(port: int) -> Optional[bytes]:
    """Return a harmless probe to elicit a banner, or None to just listen."""
    if port in _HTTP_PORTS:
        return b"GET / HTTP/1.0\r\nHost: iotpwned.local\r\nUser-Agent: IoTpwned\r\n\r\n"
    if port in (554, 8554):  # RTSP
        return (
            b"OPTIONS rtsp://iotpwned/ RTSP/1.0\r\nCSeq: 1\r\n"
            b"User-Agent: IoTpwned\r\n\r\n"
        )
    return None


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Connect to ``ip:port`` and return a short, cleaned banner string.

    Returns "" if the port is closed or nothing readable comes back.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            probe = _probe_for(port)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    return ""
            try:
                data = sock.recv(1024)
            except socket.timeout:
                return ""
            except OSError:
                return ""
    except OSError:
        return ""

    return _clean_banner(data)


def _clean_banner(data: bytes) -> str:
    if not data:
        return ""
    text = data.decode("latin-1", errors="replace")
    # Collapse whitespace and strip control characters so the banner is safe to
    # print and store. Keep it reasonably short.
    text = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
    text = " ".join(text.split())
    return text[:300].strip()


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[OpenPort]:
    """Return an :class:`OpenPort` if the TCP port is open, else None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

    spec = PORT_SPECS.get(port)
    service = spec.service if spec else "unknown"
    banner = grab_banner(ip, port, timeout=max(timeout, 2.0))
    return OpenPort(port=port, service=service, banner=banner)


def scan_host(
    ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    workers: int = 32,
) -> List[OpenPort]:
    """Scan ``ports`` on a single host; return the open ones (sorted)."""
    ports = ports or DEFAULT_SCAN_PORTS
    open_ports: List[OpenPort] = []

    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        futures = {
            pool.submit(scan_port, ip, port, timeout): port for port in ports
        }
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception:
                result = None
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda p: p.port)
    return open_ports


def scan_hosts(
    hosts: List[Host],
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    host_workers: int = 16,
    progress=None,
) -> List[Host]:
    """Scan every host in ``hosts`` in parallel, filling ``open_ports`` in place.

    Returns the same list for convenience.
    """
    ports = ports or DEFAULT_SCAN_PORTS
    done = 0

    with ThreadPoolExecutor(max_workers=host_workers) as pool:
        futures = {
            pool.submit(scan_host, h.ip, ports, timeout): h for h in hosts
        }
        for fut in as_completed(futures):
            host = futures[fut]
            done += 1
            try:
                host.open_ports = fut.result()
            except Exception:
                host.open_ports = []
            if progress:
                progress(done, len(hosts), host.ip)

    return hosts
