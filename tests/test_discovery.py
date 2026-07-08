import ipaddress

import pytest

from homeguard import discovery
from homeguard.discovery import default_subnet, normalise_mac


def test_normalise_mac_variants():
    assert normalise_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalise_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"
    assert normalise_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"


def test_arp_regex_windows_line():
    line = "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
    m = discovery._ARP_RE.search(line)
    assert m and m.group("ip") == "192.168.1.1"
    assert normalise_mac(m.group("mac")) == "AA:BB:CC:DD:EE:FF"


def test_arp_regex_posix_line():
    line = "? (192.168.0.23) at 11:22:33:44:55:66 [ether] on eth0"
    m = discovery._ARP_RE.search(line)
    assert m and m.group("ip") == "192.168.0.23"
    assert normalise_mac(m.group("mac")) == "11:22:33:44:55:66"


def test_read_arp_table_parses(monkeypatch):
    fake = (
        "Interface: 192.168.1.10 --- 0x5\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
        "  192.168.1.20          11-22-33-44-55-66     dynamic\n"
        "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
    )

    class _Proc:
        stdout = fake

    monkeypatch.setattr(discovery.subprocess, "run", lambda *a, **k: _Proc())
    table = discovery.read_arp_table()
    assert table["192.168.1.1"] == "AA:BB:CC:DD:EE:FF"
    assert table["192.168.1.20"] == "11:22:33:44:55:66"
    # broadcast MAC filtered out
    assert "192.168.1.255" not in table


def test_default_subnet_is_a_valid_network(monkeypatch):
    monkeypatch.setattr(discovery, "get_primary_ip", lambda: "192.168.7.42")
    cidr = default_subnet()
    net = ipaddress.ip_network(cidr, strict=False)
    assert str(net) == "192.168.7.0/24"


def test_default_subnet_none_without_ip(monkeypatch):
    monkeypatch.setattr(discovery, "get_primary_ip", lambda: None)
    assert default_subnet() is None


def test_guess_gateway():
    assert discovery._guess_gateway("192.168.1.0/24") == "192.168.1.1"
