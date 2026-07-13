"""Endpoint discovery: expand a target spec into concrete host:port pairs,
then keep only the ones with an open TCP port worth a TLS handshake.

Turns `--discover 10.0.0.0/28:443,8443` from "endpoints you remembered to
list" into "endpoints that actually answer" — the discovery gap is why
inventory takes orgs 12–24 months.

Scope guard: this probes hosts. Only point it at ranges you are authorized
to scan. A /16 or larger is rejected outright to avoid accidental sweeps.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator

_CONNECT_TIMEOUT = 1.5
_MAX_HOSTS = 4096          # refuse anything that would expand past this
_DEFAULT_PORTS = (443,)


class DiscoveryError(Exception):
    pass


def parse_spec(spec: str) -> tuple[list[str], list[int]]:
    """Parse `HOST-or-CIDR[:PORTS]` where PORTS is a comma/range list, e.g.
    `10.0.0.0/28:443,8443` or `example.com:443,8000-8010`."""
    host_part, _, port_part = spec.partition(":")
    hosts = _expand_hosts(host_part)
    ports = _expand_ports(port_part) if port_part else list(_DEFAULT_PORTS)
    return hosts, ports


def _expand_hosts(host_part: str) -> list[str]:
    if "/" in host_part:
        net = ipaddress.ip_network(host_part, strict=False)
        if net.num_addresses > _MAX_HOSTS:
            raise DiscoveryError(
                f"{host_part} expands to {net.num_addresses} hosts "
                f"(limit {_MAX_HOSTS}) — narrow the range")
        hosts = [str(h) for h in net.hosts()]
        return hosts or [str(net.network_address)]  # /32, /31
    return [host_part]


def _expand_ports(port_part: str) -> list[int]:
    ports: list[int] = []
    for chunk in port_part.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if hi_i < lo_i or hi_i - lo_i > 1024:
                raise DiscoveryError(f"invalid or too-wide port range: {chunk}")
            ports.extend(range(lo_i, hi_i + 1))
        elif chunk:
            ports.append(int(chunk))
    return ports


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def discover(specs: list[str], max_workers: int = 64) -> list[str]:
    """Expand every spec, probe each host:port, return the live ones as
    `host:port` strings ready to hand to TlsScanner."""
    candidates: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for spec in specs:
        hosts, ports = parse_spec(spec)
        for host in hosts:
            for port in ports:
                if (host, port) not in seen:
                    seen.add((host, port))
                    candidates.append((host, port))

    live: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = pool.map(lambda hp: (hp, _port_open(*hp)), candidates)
        for (host, port), is_open in results:
            if is_open:
                live.append(f"{host}:{port}")
    return live
