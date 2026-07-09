from iotpwned import wifi
from iotpwned.models import Host, ScanResult, Severity, WifiInfo
from iotpwned.risk import score_and_grade
from iotpwned.wifi import (
    classify_auth,
    evaluate_wifi,
    parse_airport,
    parse_netsh_interfaces,
    parse_nmcli,
)

NETSH_WPA2 = """\
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wireless-AC 9462
    Physical address       : ec:63:d7:e0:fc:22
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Band                   : 5 GHz
    Signal                 : 90%
"""

NETSH_OPEN = """\
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : FreeCoffee
    Authentication         : Open
    Cipher                 : None
"""

NETSH_WEP = """\
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : OldRouter
    Authentication         : Open
    Cipher                 : WEP
"""

NETSH_DISCONNECTED = """\
    Name                   : Wi-Fi
    Description            : Intel(R) Wireless-AC 9462
    State                  : disconnected
    Radio status           : Hardware On
                             Software Off
"""


def test_classify_variants():
    assert classify_auth("WPA3-Personal", "GCMP") == "wpa3"
    assert classify_auth("WPA2-Personal", "CCMP") == "wpa2"
    assert classify_auth("WPA2-Enterprise", "CCMP") == "wpa2-enterprise"
    assert classify_auth("WPA-Personal", "TKIP") == "wpa"
    assert classify_auth("Open", "WEP") == "wep"
    assert classify_auth("Open", "None") == "open"


def test_parse_netsh_wpa2():
    info = parse_netsh_interfaces(NETSH_WPA2)
    assert info.connected
    assert info.ssid == "HomeNet"
    assert info.category == "wpa2"
    assert info.band == "5 GHz"
    assert info.platform == "windows"


def test_parse_netsh_open():
    info = parse_netsh_interfaces(NETSH_OPEN)
    assert info.connected and info.category == "open"


def test_parse_netsh_wep():
    info = parse_netsh_interfaces(NETSH_WEP)
    assert info.category == "wep"


def test_parse_netsh_disconnected():
    info = parse_netsh_interfaces(NETSH_DISCONNECTED)
    assert info.supported and not info.connected


def test_parse_nmcli_active_row():
    out = "*:HomeNet:WPA2\n :Neighbour:WPA1 WPA2\n"
    info = parse_nmcli(out)
    assert info.connected and info.ssid == "HomeNet" and info.category == "wpa2"


def test_parse_nmcli_open_active():
    info = parse_nmcli("*:CafeNet:\n")
    assert info.connected and info.category == "open"


def test_parse_nmcli_not_connected():
    info = parse_nmcli(" :SomeNet:WPA2\n")
    assert not info.connected


def test_parse_airport_wpa2():
    out = "     state: running\n     link auth: wpa2-psk\n     SSID: HomeNet\n"
    info = parse_airport(out)
    assert info.connected and info.category == "wpa2" and info.ssid == "HomeNet"


def test_evaluate_open_is_critical():
    info = WifiInfo(connected=True, ssid="FreeCoffee", authentication="Open",
                    category="open")
    findings = evaluate_wifi(info)
    assert findings and findings[0].severity is Severity.CRITICAL
    assert "FreeCoffee" in findings[0].title


def test_evaluate_wep_is_critical():
    info = WifiInfo(connected=True, category="wep", authentication="Open")
    assert evaluate_wifi(info)[0].severity is Severity.CRITICAL


def test_evaluate_wpa_is_high():
    info = WifiInfo(connected=True, category="wpa", authentication="WPA-Personal")
    assert evaluate_wifi(info)[0].severity is Severity.HIGH


def test_evaluate_wpa2_and_wpa3_clean():
    assert evaluate_wifi(WifiInfo(connected=True, category="wpa2")) == []
    assert evaluate_wifi(WifiInfo(connected=True, category="wpa3")) == []


def test_evaluate_not_connected_or_unsupported():
    assert evaluate_wifi(WifiInfo(supported=True, connected=False)) == []
    assert evaluate_wifi(WifiInfo(supported=False)) == []


def test_network_findings_count_toward_grade():
    clean = ScanResult(subnet="x", hosts=[Host(ip="10.0.0.5")])
    score_clean, _ = score_and_grade(clean.hosts, clean.network_findings)

    info = WifiInfo(connected=True, category="open", authentication="Open")
    risky = ScanResult(subnet="x", hosts=[Host(ip="10.0.0.5")],
                       network_findings=evaluate_wifi(info))
    score_risky, grade_risky = score_and_grade(risky.hosts, risky.network_findings)

    assert score_risky < score_clean
    assert grade_risky in ("D", "F")


def test_check_wifi_runs_on_this_machine():
    # Smoke: should not raise on any platform, returns a WifiInfo + list.
    info, findings = wifi.check_wifi()
    assert isinstance(info, WifiInfo)
    assert isinstance(findings, list)
