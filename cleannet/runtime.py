"""Runtime state containers used by the proxy and dashboard."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import random
import threading
import time
from datetime import datetime
from typing import Any, Callable


class ConnectionTracker:
    def __init__(self):
        self._items: dict[int, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._seq = 0

    def track(self, host: str, port: int, site_name: str | None = None, mode: str = "direct") -> int:
        with self._lock:
            self._seq += 1
            cid = self._seq
            self._items[cid] = {
                "id": cid,
                "host": host,
                "port": port,
                "site": site_name or "",
                "mode": mode,
                "started_at": time.time(),
            }
            return cid

    def release(self, cid: int | None) -> None:
        if not cid:
            return
        with self._lock:
            self._items.pop(cid, None)

    def snapshot(self) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = []
            for item in self._items.values():
                row = dict(item)
                started_at = item.get("started_at", now)
                row["age_s"] = round(now - started_at, 1)
                row["started_at_iso"] = datetime.fromtimestamp(started_at).isoformat(timespec="seconds")
                rows.append(row)
        rows.sort(key=lambda x: x.get("started_at", 0), reverse=True)
        return rows

    def count(self) -> int:
        with self._lock:
            return len(self._items)


def default_global_stats() -> dict[str, int]:
    return {
        "connections": 0,
        "fragments": 0,
        "ip_updates": 0,
        "last_ip_refresh": 0,
        "strategy_tries": 0,
        "strategy_fallbacks": 0,
    }


def default_training_state() -> dict[str, Any]:
    return {
        "active": False,
        "progress": {},
        "results": {},
        "previous_strategies": {},
        "completed": False,
    }


def default_self_train_state() -> dict[str, Any]:
    return {
        "running": False,
        "last_run": 0,
        "total_probes": 0,
        "last_site": "",
        "last_strategy": "",
        "last_result": "",
        "cycle_count": 0,
    }


@dataclass
class RuntimeState:
    config: dict[str, Any]
    bypass_domains: list[str] = field(default_factory=list)
    bypass_ips: list[str] = field(default_factory=list)
    domain_to_site: dict[str, str] = field(default_factory=dict)
    site_ips: dict[str, list[str]] = field(default_factory=dict)
    site_dns: dict[str, list[str]] = field(default_factory=dict)
    site_names: list[str] = field(default_factory=list)
    ping_ms: int = -1
    ping_history: Any = field(default_factory=lambda: deque(maxlen=120))
    stats: dict[str, Any] = field(default_factory=default_global_stats)
    site_stats: dict[str, Any] = field(default_factory=dict)
    connection_tracker: ConnectionTracker = field(default_factory=ConnectionTracker)
    test_results: dict[str, Any] = field(default_factory=dict)
    strategy_history: Any = field(default_factory=lambda: deque(maxlen=100))
    domain_ips: dict[str, list[str]] = field(default_factory=dict)
    dns_privacy_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    site_privacy_state: dict[str, Any] = field(default_factory=dict)
    blocked_domains: dict[str, float] = field(default_factory=dict)
    site_semaphores: dict[str, Any] = field(default_factory=dict)
    training_state: dict[str, Any] = field(default_factory=default_training_state)
    self_train_state: dict[str, Any] = field(default_factory=default_self_train_state)
    ai_train_intensity: str = "light"

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any],
        build_lists: Callable[[dict[str, Any]], tuple[list[str], list[str], dict[str, str], dict[str, list[str]], dict[str, list[str]]]],
    ) -> "RuntimeState":
        state = cls(config=config)
        state.apply_config(config, build_lists, clear_dns=False)
        return state

    def apply_config(
        self,
        config: dict[str, Any],
        build_lists: Callable[[dict[str, Any]], tuple[list[str], list[str], dict[str, str], dict[str, list[str]], dict[str, list[str]]]],
        clear_dns: bool = True,
    ) -> None:
        self.config = config
        (
            self.bypass_domains,
            self.bypass_ips,
            self.domain_to_site,
            self.site_ips,
            self.site_dns,
        ) = build_lists(config)
        self.site_names = list(config.get("sites", {}).keys())
        if clear_dns:
            self.domain_ips.clear()
            self.dns_privacy_cache.clear()

    def set_stats(self, stats: dict[str, Any], site_stats: dict[str, Any]) -> None:
        self.stats = stats
        self.site_stats = site_stats

    def active_connections(self) -> list[dict[str, Any]]:
        return self.connection_tracker.snapshot()

    def set_ping_ms(self, value: int) -> None:
        self.ping_ms = value

    def set_bypass_ips(self, ips: list[str]) -> None:
        self.bypass_ips = list(ips)

    def set_ai_train_intensity(self, value: str) -> None:
        self.ai_train_intensity = value

    def get_privacy_settings(self) -> dict[str, bool]:
        privacy = self.config.get("privacy", {})
        return {
            "hide_dns": bool(privacy.get("hide_dns", False)),
            "hide_sni": bool(privacy.get("hide_sni", False)),
        }

    def record_strategy_fragments(self, count: int) -> None:
        self.stats["fragments"] += count

    def find_site_for_host(self, host: str, cdn_keyword_map: dict[str, str] | None = None) -> str | None:
        host_lower = host.lower()
        if host_lower in self.domain_to_site:
            return self.domain_to_site[host_lower]
        for domain, site_name in self.domain_to_site.items():
            if host_lower.endswith("." + domain):
                return site_name
        for cdn_keyword, parent_site in (cdn_keyword_map or {}).items():
            if cdn_keyword in host_lower and parent_site in self.config.get("sites", {}):
                if self.config["sites"][parent_site].get("enabled", True):
                    return parent_site
        for site_name in self.site_names:
            if len(site_name) >= 3 and site_name.lower() in host_lower:
                if site_name in self.config.get("sites", {}) and self.config["sites"][site_name].get("enabled", True):
                    return site_name
        return None

    def is_main_domain(self, host: str, site_name: str) -> bool:
        for part in host.lower().split("."):
            if site_name.lower() in part:
                return True
        return False

    def get_bypass_ip(self, host: str, cdn_keyword_map: dict[str, str] | None = None) -> str | None:
        host_lower = host.lower()
        if host_lower in self.domain_ips and self.domain_ips[host_lower]:
            return random.choice(self.domain_ips[host_lower])
        if self.find_site_for_host(host_lower, cdn_keyword_map):
            return host_lower
        site = self.find_site_for_host(host, cdn_keyword_map)
        if site and self.site_ips.get(site):
            return random.choice(self.site_ips[site])
        return None

    def get_domain_ips(self, host: str) -> list[str]:
        host_lower = host.lower()
        if host_lower in self.domain_ips and self.domain_ips[host_lower]:
            return self.domain_ips[host_lower]
        return []

    def get_site_ips(self, host: str, cdn_keyword_map: dict[str, str] | None = None, cross_cdn_map: dict[str, str] | None = None) -> list[str]:
        site = self.find_site_for_host(host, cdn_keyword_map)
        ips = []
        if site and site in self.site_ips:
            ips.extend(self.site_ips[site])
        if site in (cross_cdn_map or {}):
            sister = (cross_cdn_map or {})[site]
            if sister in self.site_ips:
                ips.extend(self.site_ips[sister])
        return list(set(ips))
