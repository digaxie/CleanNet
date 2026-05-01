"""Live local network connection snapshots for dashboard diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import csv
import fnmatch
import ipaddress
import platform
import subprocess
import time
from typing import Any, Callable


@dataclass(frozen=True)
class NetworkFlow:
    process_name: str
    pid: int
    protocol: str
    local_address: str
    local_port: int | None
    remote_address: str
    remote_port: int | None
    state: str
    exception_entry: str
    is_exception: bool


def _subprocess_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run_command(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=_subprocess_flags(),
    )


def _parse_endpoint(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if not value or value == "*:*":
        return "*", None
    if value.startswith("["):
        end = value.find("]")
        if end >= 0:
            host = value[1:end]
            port_text = value[end + 2 :] if value[end + 1 : end + 2] == ":" else ""
            return host, _parse_port(port_text)
    if ":" not in value:
        return value, None
    host, port_text = value.rsplit(":", 1)
    return host, _parse_port(port_text)


def _parse_port(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_local_address(address: str) -> bool:
    if address in {"*", "0.0.0.0", "::", "::1", "127.0.0.1", "localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _matches_bypass(address: str, entries: list[str]) -> bool:
    if not address or address == "*":
        return False
    normalized = address.lower()
    for raw_entry in entries:
        entry = str(raw_entry or "").strip().lower()
        if not entry:
            continue
        if entry == "<local>" and _is_local_address(normalized):
            return True
        if entry == normalized or fnmatch.fnmatch(normalized, entry):
            return True
    return False


def exception_entry_for_flow(flow: NetworkFlow | dict[str, Any]) -> str:
    remote_address = flow["remote_address"] if isinstance(flow, dict) else flow.remote_address
    remote_port = flow["remote_port"] if isinstance(flow, dict) else flow.remote_port
    if not remote_address or remote_address == "*" or remote_port is None:
        return ""
    if _is_local_address(remote_address):
        return ""
    return remote_address


def _parse_netstat(text: str, process_names: dict[int, str], bypass_entries: list[str]) -> list[NetworkFlow]:
    flows: list[NetworkFlow] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith(("TCP", "UDP")):
            continue
        parts = line.split()
        protocol = parts[0].upper()
        if protocol == "TCP" and len(parts) >= 5:
            local_raw, remote_raw, state, pid_raw = parts[1], parts[2], parts[3], parts[4]
        elif protocol == "UDP" and len(parts) >= 4:
            local_raw, remote_raw, state, pid_raw = parts[1], parts[2], "LISTEN", parts[3]
        else:
            continue
        try:
            pid = int(pid_raw)
        except ValueError:
            continue
        local_address, local_port = _parse_endpoint(local_raw)
        remote_address, remote_port = _parse_endpoint(remote_raw)
        probe = NetworkFlow(
            process_name=process_names.get(pid, ""),
            pid=pid,
            protocol=protocol,
            local_address=local_address,
            local_port=local_port,
            remote_address=remote_address,
            remote_port=remote_port,
            state=state,
            exception_entry="",
            is_exception=_matches_bypass(remote_address, bypass_entries),
        )
        entry = exception_entry_for_flow(probe)
        flows.append(
            NetworkFlow(
                process_name=probe.process_name,
                pid=probe.pid,
                protocol=probe.protocol,
                local_address=probe.local_address,
                local_port=probe.local_port,
                remote_address=probe.remote_address,
                remote_port=probe.remote_port,
                state=probe.state,
                exception_entry=entry,
                is_exception=probe.is_exception,
            )
        )
    return flows


def _parse_tasklist_csv(text: str) -> dict[int, str]:
    result: dict[int, str] = {}
    for row in csv.reader(text.splitlines()):
        if len(row) < 2:
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue
        result[pid] = row[0]
    return result


class NetworkMonitor:
    def __init__(
        self,
        *,
        system: str | None = None,
        runner: Callable[[list[str], float], subprocess.CompletedProcess[str]] = _run_command,
        cache_ttl: float = 3.0,
    ):
        self.system = system or platform.system()
        self.runner = runner
        self.cache_ttl = cache_ttl
        self._cached_flows: list[NetworkFlow] = []
        self._cached_at = 0.0
        self._last_error = ""

    def supported(self) -> bool:
        return self.system.lower() == "windows"

    def snapshot(
        self,
        proxy_bypass: list[str] | None = None,
        always_bypass: list[str] | None = None,
        *,
        limit: int = 250,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        if not self.supported():
            return {
                "supported": False,
                "flows": [],
                "summary": self._summary([], supported=False),
                "error": "network flow snapshot is only supported on Windows",
            }

        now = time.time()
        bypass_entries = list(always_bypass or []) + list(proxy_bypass or [])
        if use_cache and self._cached_flows and now - self._cached_at < self.cache_ttl:
            flows = self._apply_exception_flags(self._cached_flows, bypass_entries)
        else:
            try:
                netstat = self.runner(["netstat", "-ano"], 4.0)
                process_names = self._load_process_names()
                flows = _parse_netstat(netstat.stdout, process_names, bypass_entries)
                self._cached_flows = flows
                self._cached_at = now
                self._last_error = ""
            except Exception as exc:
                flows = []
                self._last_error = str(exc)

        flows.sort(key=lambda item: (item.process_name.lower(), item.pid, item.protocol, item.remote_address))
        limited = flows[: max(0, limit)]
        return {
            "supported": True,
            "flows": [asdict(item) for item in limited],
            "summary": self._summary(flows, supported=True),
            "error": self._last_error,
        }

    def last_summary(self) -> dict[str, Any]:
        return self._summary(self._cached_flows, supported=self.supported())

    def _load_process_names(self) -> dict[int, str]:
        try:
            tasklist = self.runner(["tasklist", "/FO", "CSV", "/NH"], 4.0)
        except Exception:
            return {}
        return _parse_tasklist_csv(tasklist.stdout)

    def _apply_exception_flags(self, flows: list[NetworkFlow], bypass_entries: list[str]) -> list[NetworkFlow]:
        updated: list[NetworkFlow] = []
        for flow in flows:
            updated.append(
                NetworkFlow(
                    process_name=flow.process_name,
                    pid=flow.pid,
                    protocol=flow.protocol,
                    local_address=flow.local_address,
                    local_port=flow.local_port,
                    remote_address=flow.remote_address,
                    remote_port=flow.remote_port,
                    state=flow.state,
                    exception_entry=flow.exception_entry,
                    is_exception=_matches_bypass(flow.remote_address, bypass_entries),
                )
            )
        return updated

    def _summary(self, flows: list[NetworkFlow], *, supported: bool) -> dict[str, Any]:
        process_counts: dict[str, int] = {}
        addable = 0
        for flow in flows:
            name = flow.process_name or f"PID {flow.pid}"
            process_counts[name] = process_counts.get(name, 0) + 1
            if flow.exception_entry and not flow.is_exception:
                addable += 1
        top_processes = [
            {"process_name": name, "count": count}
            for name, count in sorted(process_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        ]
        return {
            "supported": supported,
            "flow_count": len(flows),
            "addable_count": addable,
            "exception_count": sum(1 for flow in flows if flow.is_exception),
            "top_processes": top_processes,
            "last_updated": int(self._cached_at) if self._cached_at else 0,
        }
