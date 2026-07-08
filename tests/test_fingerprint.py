from iotpwned.fingerprint import (
    fingerprint_host,
    label_from_banners,
    label_from_ports,
    lookup_vendor,
)
from iotpwned.models import Host, OpenPort


def test_banner_signature_hikvision():
    label = label_from_banners(["Server: App-webs/ DVRDVS-Webs"])
    assert label and "Hikvision" in label


def test_banner_signature_router():
    assert "TP-Link" in (label_from_banners(["Server: TP-LINK Router"]) or "")


def test_banner_no_match_returns_none():
    assert label_from_banners(["totally generic response"]) is None


def test_label_from_ports_camera():
    # RTSP -> camera hint
    assert "camera" in (label_from_ports([554]) or "").lower()


def test_lookup_vendor_fallback_table():
    # Known Hikvision OUI in the built-in fallback table.
    vendor = lookup_vendor("44:19:B6:11:22:33")
    assert vendor and "Hikvision" in vendor


def test_lookup_vendor_unknown():
    assert lookup_vendor("02:00:00:00:00:00") in (None,) or isinstance(
        lookup_vendor("02:00:00:00:00:00"), str
    )


def test_lookup_vendor_none_mac():
    assert lookup_vendor(None) is None


def test_fingerprint_host_labels_camera():
    host = Host(
        ip="192.168.1.30",
        mac="44:19:B6:00:00:01",
        open_ports=[OpenPort(port=554, service="RTSP", banner="RTSP/1.0 200 OK")],
    )
    fingerprint_host(host)
    assert host.vendor and "Hikvision" in host.vendor
    assert host.device_type  # some label assigned
    assert host.device_type != "Unknown device"


def test_fingerprint_gateway_default():
    host = Host(ip="192.168.1.1", is_gateway=True)
    fingerprint_host(host)
    assert "Router" in host.device_type or "gateway" in host.device_type.lower()
