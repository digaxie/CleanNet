"""Wait for real network connectivity before taking over the system proxy.

Shared by every platform: at login, autostart runs before DHCP/DNS are ready, and
enabling the system proxy in that window blackholes all traffic until restart.
"""

from __future__ import annotations

import socket
import time


def _dns_and_route_ready(probe_host: str, probe_port: int, dns_probe_hosts: list[str]) -> bool:
    # Passthrough traffic relies on the system resolver, so DNS must work...
    resolved = False
    for name in dns_probe_hosts:
        try:
            socket.getaddrinfo(name, probe_port)
            resolved = True
            break
        except OSError:
            continue
    if not resolved:
        return False
    # ...and we must be able to reach a public endpoint over TCP.
    try:
        with socket.create_connection((probe_host, probe_port), timeout=3):
            return True
    except OSError:
        return False


def wait_for_network_ready(
    probe_host: str = "1.1.1.1",
    probe_port: int = 443,
    dns_probe_hosts: list[str] | None = None,
    max_wait: float = 120.0,
    interval: float = 2.0,
    logger=None,
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> bool:
    """Block until the machine has real connectivity, bounded by ``max_wait``.

    At Windows logon the autostart entry runs before DHCP/DNS are ready. Enabling
    the system proxy in that window forces every connection through the local
    engine while it still cannot reach upstream, leaving the machine with no
    internet until the user restarts the app. Gate proxy activation on this check.

    Probes use raw sockets, so they are unaffected by any current system proxy.
    Returns True once connectivity is confirmed, or False if ``max_wait`` elapses.
    """
    if not (probe_host or "").strip():
        probe_host = "1.1.1.1"
    dns_probe_hosts = dns_probe_hosts or ["microsoft.com", "example.com"]
    deadline = monotonic() + max_wait
    attempts = 0
    while True:
        attempts += 1
        if _dns_and_route_ready(probe_host, probe_port, dns_probe_hosts):
            if logger and attempts > 1:
                logger.info(f"[STARTUP] Network ready after {attempts} probe(s)")
            return True
        if monotonic() >= deadline:
            if logger:
                logger.warning(
                    f"[STARTUP] Network not confirmed within {int(max_wait)}s; enabling proxy anyway"
                )
            return False
        sleep(interval)
