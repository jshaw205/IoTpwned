import socket
import threading
import time

import pytest

from homeguard.scanner import _clean_banner, scan_host, scan_port


class _TinyServer:
    """A localhost TCP server that optionally sends a banner, for testing."""

    def __init__(self, banner: bytes = b""):
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                self.sock.settimeout(0.5)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if self.banner:
                    conn.sendall(self.banner)
                time.sleep(0.05)
            except OSError:
                pass
            finally:
                conn.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def test_scan_port_detects_open_port():
    with _TinyServer(banner=b"220 FakeFTP ready\r\n") as srv:
        result = scan_port("127.0.0.1", srv.port, timeout=1.0)
    assert result is not None
    assert result.port == srv.port


def test_scan_port_grabs_banner():
    with _TinyServer(banner=b"SSH-2.0-OpenSSH_8.9\r\n") as srv:
        result = scan_port("127.0.0.1", srv.port, timeout=1.0)
    assert result is not None
    assert "OpenSSH" in result.banner


def test_scan_port_closed_returns_none():
    # Pick a port nothing is listening on.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    free_port = s.getsockname()[1]
    s.close()
    assert scan_port("127.0.0.1", free_port, timeout=0.5) is None


def test_scan_host_finds_listening_port():
    with _TinyServer() as srv:
        open_ports = scan_host("127.0.0.1", ports=[srv.port], timeout=1.0)
    assert [op.port for op in open_ports] == [srv.port]


def test_clean_banner_strips_control_chars():
    cleaned = _clean_banner(b"hello\x00\x01world\r\n")
    assert "\x00" not in cleaned
    assert "hello" in cleaned and "world" in cleaned


def test_clean_banner_empty():
    assert _clean_banner(b"") == ""
