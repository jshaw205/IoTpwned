"""The scan pipeline, decoupled from any front-end.

Both the CLI and the local web UI call :func:`run_pipeline` so they run exactly
the same discovery -> port scan -> fingerprint -> Wi-Fi -> risk-score sequence.
Progress reporting and the (consent-gated) online CVE step are injected by the
caller, keeping this module free of I/O policy.
"""

from __future__ import annotations

import datetime
import time
from typing import Callable, List, Optional

from . import cve_online, wan, wifi
from .discovery import default_subnet, discover_hosts
from .fingerprint import fingerprint_hosts
from .models import ScanResult
from .risk import finalize, rescore
from .scanner import scan_hosts

ProgressCb = Optional[Callable[[int, int, str], None]]
SubnetStartCb = Optional[Callable[[str, int, int], None]]


def _resolve_targets(
    cidr: Optional[str], cidrs: Optional[List[str]]
) -> List[str]:
    """Normalise the requested subnet(s) into an ordered, de-duplicated list.

    Accepts a single ``cidr`` (back-compat) and/or a ``cidrs`` list. Falls back
    to the auto-detected local subnet when nothing is given.
    """
    raw: List[str] = []
    if cidrs:
        raw.extend(cidrs)
    if cidr:
        raw.append(cidr)

    seen = set()
    targets: List[str] = []
    for c in raw:
        c = (c or "").strip()
        if c and c not in seen:
            seen.add(c)
            targets.append(c)

    if targets:
        return targets
    auto = default_subnet()
    return [auto] if auto else []


def run_pipeline(
    *,
    cidr: Optional[str] = None,
    cidrs: Optional[List[str]] = None,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    ping_timeout: int = 700,
    do_ping: bool = True,
    resolve: bool = True,
    do_wifi: bool = True,
    on_subnet_start: SubnetStartCb = None,
    on_discovery_progress: ProgressCb = None,
    on_hosts_discovered: Optional[Callable[[list], None]] = None,
    on_scan_progress: ProgressCb = None,
) -> ScanResult:
    """Run the full local scan and return a finalized :class:`ScanResult`.

    Scans a single subnet (``cidr``) or several at once (``cidrs`` — useful for
    multiple VLANs, provided this machine can actually route to each one). Hosts
    from every subnet are merged into one result, each tagged with its origin
    subnet so the report can group them. Wi-Fi is a machine-level check and runs
    once regardless of subnet count.

    Raises :class:`RuntimeError` if no subnet is given and none can be
    auto-detected. Does **not** perform the online CVE lookup — call
    :func:`apply_online_cve` separately once consent is established.
    """
    targets = _resolve_targets(cidr, cidrs)
    if not targets:
        raise RuntimeError(
            "Could not auto-detect the local subnet. "
            "Provide one explicitly, e.g. 192.168.1.0/24"
        )

    started = time.time()
    started_iso = datetime.datetime.now().isoformat(timespec="seconds")

    all_hosts: list = []
    for idx, target in enumerate(targets):
        if on_subnet_start:
            on_subnet_start(target, idx, len(targets))

        hosts = discover_hosts(
            cidr=target,
            timeout_ms=ping_timeout,
            do_ping=do_ping,
            resolve_names=resolve,
            progress=on_discovery_progress if do_ping else None,
        )
        for host in hosts:
            host.subnet = target
        if on_hosts_discovered:
            on_hosts_discovered(hosts)

        scan_hosts(hosts, ports=ports, timeout=timeout, progress=on_scan_progress)
        fingerprint_hosts(hosts)
        all_hosts.extend(hosts)

    result = ScanResult(
        subnet=", ".join(targets),
        subnets=list(targets),
        hosts=all_hosts,
        started_at=started_iso,
        finished_at=datetime.datetime.now().isoformat(timespec="seconds"),
        duration_seconds=time.time() - started,
    )

    if do_wifi:
        info, wifi_findings = wifi.check_wifi()
        result.wifi = info
        result.network_findings.extend(wifi_findings)

    finalize(result)
    return result


def apply_online_cve(
    result: ScanResult,
    *,
    limit: int = 5,
    api_key: Optional[str] = None,
    delay: Optional[float] = None,
    progress: ProgressCb = None,
) -> int:
    """Enrich ``result`` with live NVD CVEs and re-score. Returns count added.

    The caller is responsible for having obtained consent first — this only
    performs the (already-consented) network lookup.
    """
    keyword_map = cve_online.derive_keywords(result.hosts)
    if not keyword_map:
        return 0
    added = cve_online.enrich(
        keyword_map, limit=limit, api_key=api_key, delay=delay, progress=progress
    )
    rescore(result)
    return added


def apply_wan_check(result, *, public_ip=None, timeout: float = 15.0):
    """Run the opt-in external exposure check and fold it into the result.

    The caller is responsible for consent — this only performs the (already
    consented) lookups. Returns the :class:`WanInfo` for status reporting.
    """
    info, findings = wan.check_wan(public_ip=public_ip, timeout=timeout)
    result.wan = info
    result.network_findings.extend(findings)
    rescore(result)
    return info


def apply_cred_check(result, *, timeout: float = 5.0):
    """Run the opt-in default-password check across candidate hosts.

    Caller is responsible for consent. Appends findings to the relevant hosts and
    re-scores. Returns ``(devices_tested, weak_found)``.
    """
    from . import credcheck

    tested = weak = 0
    for host in result.hosts:
        findings, did_test = credcheck.check_host_credentials(host, timeout=timeout)
        if did_test:
            tested += 1
        if findings:
            weak += len(findings)
            host.findings.extend(findings)
            host.findings.sort(key=lambda f: (-f.severity.value, f.port or 0))
    rescore(result)
    return tested, weak
