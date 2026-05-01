"""Dashboard asset loading and API routing."""

from __future__ import annotations

import asyncio
import ctypes
from dataclasses import dataclass
import json
import os
import sys
import tempfile
import time
from functools import lru_cache
from typing import Any, Awaitable, Callable

from .config_service import (
    ALLOWED_HEALTH_CHECK_INTERVALS,
    ALLOWED_IP_UPDATE_INTERVALS,
    ConfigMutationContext,
    ConfigMutationService,
    MutationResult,
)
from .config_defaults import get_bypass_preset_options
from .diagnostics import build_diagnostics_snapshot
from .strategy_advisor import build_strategy_recommendations
from .windows_integration import get_proxy_summary


@lru_cache(maxsize=1)
def load_dashboard_html(app_dir: str, version: str) -> str:
    base_dir = getattr(sys, "_MEIPASS", app_dir)
    path = os.path.join(base_dir, "assets", "dashboard.html")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    return html.replace("__CLEANNET_VERSION__", version)


Reader = Any
Writer = Any


@dataclass
class DashboardRuntimeContext:
    version: str
    dashboard_html: str
    logger: Any
    get_config: Callable[[], dict[str, Any]]
    save_config: Callable[[], None]
    reload_config: Callable[[], bool]
    resolve_bypass_ips: Callable[[], Awaitable[Any]]
    resolve_domain_doh: Callable[[str], list[str]]
    strategy_cache: Any
    ai_engine: Any
    get_ai_train_intensity: Callable[[], str]
    set_ai_train_intensity: Callable[[str], None]
    ai_train_profiles: dict[str, Any]
    training_state: dict[str, Any]
    self_train_state: dict[str, Any]
    train_all_sites: Callable[[], Awaitable[Any]]
    apply_training: Callable[[str], None]
    revert_training: Callable[[str], None]
    always_bypass: list[str]
    bypass_presets: dict[str, list[str]]
    get_autostart: Callable[[], bool]
    set_autostart: Callable[[bool], Any]
    get_privacy_settings: Callable[[], dict[str, bool]]
    get_performance_settings: Callable[[], dict[str, Any]]
    get_network_flows: Callable[[], dict[str, Any]]
    test_site_connection: Callable[[str], Awaitable[Any]]
    get_running: Callable[[], bool]
    get_status: Callable[[], str]
    get_ping_ms: Callable[[], int]
    get_start_time: Callable[[], float | None]
    get_bypass_ips: Callable[[], list[str]]
    get_active_connections: Callable[[], list[dict[str, Any]]]
    dashboard_log_handler: Any
    stats: dict[str, Any]
    site_stats: dict[str, Any]
    strategy_history: Any
    test_results: dict[str, Any]
    site_privacy_state: dict[str, Any]
    script_dir: str
    local_host: str
    local_port: int
    strategy_names: list[str]


def _close_writer(writer: Writer | None) -> None:
    try:
        if writer:
            writer.close()
    except Exception:
        pass


class DashboardServer:
    def __init__(self, context: DashboardRuntimeContext):
        self.ctx = context
        self.config_service = ConfigMutationService(
            ConfigMutationContext(
                logger=context.logger,
                get_config=context.get_config,
                save_config=context.save_config,
                reload_config=context.reload_config,
                always_bypass=context.always_bypass,
                bypass_presets=context.bypass_presets,
            )
        )

    async def _read_json(self, reader: Reader, limit: int) -> dict[str, Any]:
        body_bytes = await reader.read(limit)
        return json.loads(body_bytes.decode()) if body_bytes else {}

    async def _send(
        self,
        writer: Writer,
        status: str,
        body: bytes = b"",
        *,
        content_type: str | None = None,
        headers: list[tuple[str, str]] | None = None,
        include_length: bool = True,
    ) -> None:
        header_lines = [f"HTTP/1.1 {status}"]
        if content_type:
            header_lines.append(f"Content-Type: {content_type}")
        for key, value in headers or []:
            header_lines.append(f"{key}: {value}")
        if include_length:
            header_lines.append(f"Content-Length: {len(body)}")
        writer.write(("\r\n".join(header_lines) + "\r\n\r\n").encode())
        if body:
            writer.write(body)
        await writer.drain()

    async def _send_json(self, writer: Writer, payload: Any, status: str = "200 OK") -> None:
        await self._send(
            writer,
            status,
            json.dumps(payload).encode(),
            content_type="application/json",
        )

    async def _send_ok(self, writer: Writer) -> None:
        await self._send(writer, "200 OK", b'{"ok":true}', content_type="application/json")

    def _refresh_ips_if_needed(self, result: MutationResult) -> None:
        if result.refresh_ips:
            asyncio.create_task(self.ctx.resolve_bypass_ips())

    def _performance_payload(self) -> dict[str, Any]:
        settings = self.ctx.get_performance_settings()
        settings["allowed"] = {
            "health_check_interval": sorted(ALLOWED_HEALTH_CHECK_INTERVALS),
            "ip_update_interval": sorted(ALLOWED_IP_UPDATE_INTERVALS),
            "ping_target_host": ["1.1.1.1", "8.8.8.8"],
        }
        return settings

    def _valid_performance_payload(self, payload: dict[str, Any]) -> bool:
        allowed = {
            "low_latency_mode",
            "background_training",
            "health_check_interval",
            "ip_update_interval",
            "ping_target_host",
        }
        if not any(key in payload for key in allowed):
            return False
        if "health_check_interval" in payload:
            try:
                if int(payload["health_check_interval"]) not in ALLOWED_HEALTH_CHECK_INTERVALS:
                    return False
            except (TypeError, ValueError):
                return False
        if "ip_update_interval" in payload:
            try:
                if int(payload["ip_update_interval"]) not in ALLOWED_IP_UPDATE_INTERVALS:
                    return False
            except (TypeError, ValueError):
                return False
        if "ping_target_host" in payload and not str(payload.get("ping_target_host") or "").strip():
            return False
        return True

    def build_network_diagnostics(
        self,
        *,
        proxy: dict[str, Any],
        performance: dict[str, Any],
        network_summary: dict[str, Any],
        active_connection_count: int,
    ) -> dict[str, Any]:
        self_train = self.ctx.self_train_state
        last_ip_refresh = int(self.ctx.stats.get("last_ip_refresh", 0) or 0)
        return {
            "system_proxy_owned": bool(proxy.get("owned_by_cleannet")),
            "proxy_enabled": bool(proxy.get("enabled")),
            "proxy_host": self.ctx.local_host,
            "proxy_port": self.ctx.local_port,
            "active_connection_count": active_connection_count,
            "network_flow_count": int(network_summary.get("flow_count", 0) or 0),
            "last_ping_ms": self.ctx.get_ping_ms(),
            "ping_target_host": performance.get("ping_target_host", "1.1.1.1"),
            "last_ip_refresh": last_ip_refresh,
            "last_ip_refresh_age": int(time.time() - last_ip_refresh) if last_ip_refresh > 0 else -1,
            "self_training_running": bool(self_train.get("running", False)),
            "self_training_last_run": int(self_train.get("last_run", 0) or 0),
            "self_training_last_result": self_train.get("last_result", ""),
            "background_training": bool(performance.get("background_training", False)),
            "custom_proxy_bypass_count": len(self.ctx.get_config().get("proxy_bypass", [])),
        }

    def add_network_exception(self, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        entries: list[str] = []
        source = str(payload.get("source") or "network-flow")
        if payload.get("entry"):
            entries = [str(payload.get("entry") or "").strip()]
        elif payload.get("mode") == "current-process-endpoints":
            try:
                pid = int(payload.get("pid"))
            except (TypeError, ValueError):
                return {"ok": False, "error": "invalid pid"}, False
            snapshot = self.ctx.get_network_flows()
            for flow in snapshot.get("flows", []):
                if int(flow.get("pid") or 0) == pid and flow.get("exception_entry"):
                    entries.append(str(flow["exception_entry"]))
            source = f"process:{pid}"
        else:
            return {"ok": False, "error": "missing entry or process mode"}, False

        unique_entries = []
        seen = set()
        for entry in entries:
            entry = entry.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            unique_entries.append(entry)

        result = self.config_service.add_bypass_entries(unique_entries)
        self.ctx.logger.info(
            f"[NETWORK-EXCEPTION] source={source} requested={len(unique_entries)} changed={result.changed}"
        )
        return {"ok": True, "changed": result.changed, "entries": unique_entries}, True

    def get_stats_data(self) -> dict[str, Any]:
        config = self.ctx.get_config()
        site_data = {}
        active_connections = self.ctx.get_active_connections()
        ai_intensity = self.ctx.get_ai_train_intensity()
        ai_stats = self.ctx.ai_engine.get_global_stats()
        ai_stats["train_intensity"] = ai_intensity
        ai_stats["train_profile"] = self.ctx.ai_train_profiles.get(
            ai_intensity,
            self.ctx.ai_train_profiles["light"],
        )
        strategy_recommendations = build_strategy_recommendations(
            config.get("sites", {}),
            self.ctx.site_stats,
            ai_stats,
            list(self.ctx.strategy_history),
            active_connections,
        )
        for site_name, site_info in config.get("sites", {}).items():
            strat_info = self.ctx.strategy_cache.get_site_strategy_info(site_name)
            ss = self.ctx.site_stats.get(
                site_name,
                {"connections": 0, "successes": 0, "failures": 0, "total_ms": 0},
            )
            avg_ms = round(ss["total_ms"] / ss["successes"]) if ss["successes"] > 0 else 0
            ai_insights = self.ctx.ai_engine.get_site_insights(site_name)
            site_data[site_name] = {
                "enabled": site_info.get("enabled", True),
                "current_strategy": strat_info["strategy"],
                "locked_strategy": site_info.get("strategy", "auto"),
                "strategy_time_ms": strat_info["time_ms"],
                "domains": site_info.get("domains", []),
                "domain_count": len(site_info.get("domains", [])),
                "conn_count": ss["connections"],
                "success_count": ss["successes"],
                "fail_count": ss["failures"],
                "avg_ms": avg_ms,
                "test": self.ctx.test_results.get(site_name),
                "ai": ai_insights,
                "privacy": self.ctx.site_privacy_state.get(site_name),
            }

        start_time = self.ctx.get_start_time()
        self_train = self.ctx.self_train_state
        performance = self._performance_payload()
        network_snapshot = self.ctx.get_network_flows()
        network_summary = network_snapshot.get("summary", {})
        proxy = get_proxy_summary(self.ctx.script_dir, self.ctx.local_host, self.ctx.local_port)
        network_diagnostics = self.build_network_diagnostics(
            proxy=proxy,
            performance=performance,
            network_summary=network_summary,
            active_connection_count=len(active_connections),
        )
        return {
            "status": self.ctx.get_status(),
            "ping": self.ctx.get_ping_ms(),
            "uptime": int(time.time() - start_time) if start_time else 0,
            "connections": self.ctx.stats["connections"],
            "fragments": self.ctx.stats["fragments"],
            "ip_updates": self.ctx.stats["ip_updates"],
            "strategy_tries": self.ctx.stats["strategy_tries"],
            "strategy_fallbacks": self.ctx.stats["strategy_fallbacks"],
            "ips": list(self.ctx.get_bypass_ips()),
            "sites": site_data,
            "proxy_bypass": config.get("proxy_bypass", []),
            "always_bypass": self.ctx.always_bypass,
            "bypass_preset_options": get_bypass_preset_options(self.ctx.always_bypass),
            "autostart": self.ctx.get_autostart(),
            "proxy": proxy,
            "privacy": self.ctx.get_privacy_settings(),
            "performance": performance,
            "network_diagnostics": network_diagnostics,
            "network_flows_summary": network_summary,
            "active_connections": active_connections,
            "strategy_recommendations": strategy_recommendations,
            "strategy_history": list(self.ctx.strategy_history)[-50:],
            "ai_stats": ai_stats,
            "training": {
                "active": self.ctx.training_state["active"],
                "completed": self.ctx.training_state["completed"],
            },
            "self_train": {
                "running": self_train["running"],
                "total_probes": self_train["total_probes"],
                "cycle_count": self_train["cycle_count"],
                "last_site": self_train["last_site"],
                "last_result": self_train["last_result"],
                "last_run": int(time.time() - self_train["last_run"]) if self_train["last_run"] > 0 else -1,
            },
        }

    def get_sse_data(self, last_log_id: int) -> tuple[dict[str, Any], int]:
        entries = self.ctx.dashboard_log_handler.get_entries_after(last_log_id)
        new_id = entries[-1][0] if entries else last_log_id
        data = self.get_stats_data()
        data["new_logs"] = [msg for _, msg in entries]
        return data, new_id

    def build_diagnostics_data(self) -> dict[str, Any]:
        stats_data = self.get_stats_data()
        return build_diagnostics_snapshot(
            version=self.ctx.version,
            status=self.ctx.get_status(),
            config=self.ctx.get_config(),
            stats=self.ctx.stats,
            site_stats=self.ctx.site_stats,
            proxy=stats_data.get("proxy", {}),
            performance=stats_data.get("performance", {}),
            network_diagnostics=stats_data.get("network_diagnostics", {}),
            network_flows_summary=stats_data.get("network_flows_summary", {}),
            ai_stats=stats_data.get("ai_stats", {}),
            strategy_recommendations=stats_data.get("strategy_recommendations", []),
            active_connections=stats_data.get("active_connections", []),
            logs=[msg for _, msg in self.ctx.dashboard_log_handler.get_entries_after(0)],
        )

    async def handle_http(self, reader: Reader, writer: Writer) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not request_line:
                return

            parts = request_line.decode(errors="ignore").strip().split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"
            path = path.split("?", 1)[0]

            while True:
                line = await reader.readline()
                if line == b"\r\n" or not line:
                    break

            config = self.ctx.get_config()

            if path == "/":
                await self._send(
                    writer,
                    "200 OK",
                    self.ctx.dashboard_html.encode("utf-8"),
                    content_type="text/html; charset=utf-8",
                )

            elif path == "/api/stats":
                await self._send_json(writer, self.get_stats_data())

            elif path == "/api/events":
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                    b"Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n"
                )
                await writer.drain()
                last_log_id = 0
                while self.ctx.get_running():
                    data, last_log_id = self.get_sse_data(last_log_id)
                    try:
                        writer.write(f"data: {json.dumps(data)}\n\n".encode())
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                        break
                    await asyncio.sleep(1)
                return

            elif path == "/api/refresh-ips" and method == "POST":
                asyncio.create_task(self.ctx.resolve_bypass_ips())
                await self._send_ok(writer)

            elif path == "/api/reload-config" and method == "POST":
                self.ctx.reload_config()
                asyncio.create_task(self.ctx.resolve_bypass_ips())
                await self._send_ok(writer)

            elif path == "/api/toggle-site" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    result = self.config_service.toggle_site(req_data.get("site"))
                    self._refresh_ips_if_needed(result)
                except Exception as e:
                    self.ctx.logger.error(f"Toggle error: {e}")
                await self._send_ok(writer)

            elif path == "/api/remove-site" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    self.config_service.remove_site(req_data.get("site"))
                except Exception as e:
                    self.ctx.logger.error(f"Remove site error: {e}")
                await self._send_ok(writer)

            elif path == "/api/remove-all-sites" and method == "POST":
                try:
                    self.config_service.remove_all_sites()
                except Exception as e:
                    self.ctx.logger.error(f"Remove all sites error: {e}")
                await self._send_ok(writer)

            elif path == "/api/resolve-domain" and method == "POST":
                result = {"domain": "", "ips": [], "variants": []}
                try:
                    req_data = await self._read_json(reader, 1024)
                    domain = req_data.get("domain", "").strip().lower()
                    if domain:
                        result["domain"] = domain
                        loop = asyncio.get_event_loop()
                        ips = await loop.run_in_executor(None, self.ctx.resolve_domain_doh, domain)
                        result["ips"] = ips
                        variants = []
                        for prefix in ["www", "cdn", "api", "static", "media", "app"]:
                            sub = f"{prefix}.{domain}"
                            sub_ips = await loop.run_in_executor(None, self.ctx.resolve_domain_doh, sub)
                            if sub_ips:
                                variants.append({"domain": sub, "ips": sub_ips})
                        result["variants"] = variants
                except Exception as e:
                    self.ctx.logger.error(f"Resolve domain error: {e}")
                await self._send_json(writer, result)

            elif path == "/api/add-site" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 4096)
                    result = self.config_service.add_site(req_data)
                    self._refresh_ips_if_needed(result)
                except Exception as e:
                    self.ctx.logger.error(f"Add site error: {e}")
                await self._send_ok(writer)

            elif path == "/api/add-cdn" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 2048)
                    site_name = req_data.get("site", "").strip()
                    cdn_domain = req_data.get("domain", "").strip().lower()
                    result = self.config_service.add_cdn_domain(site_name, cdn_domain)
                    self._refresh_ips_if_needed(result)
                except Exception as e:
                    self.ctx.logger.error(f"Add CDN error: {e}")
                await self._send_ok(writer)

            elif path == "/api/remove-domain" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 2048)
                    site_name = req_data.get("site", "").strip()
                    domain = req_data.get("domain", "").strip().lower()
                    result = self.config_service.remove_domain(site_name, domain)
                    self._refresh_ips_if_needed(result)
                except Exception as e:
                    self.ctx.logger.error(f"Remove domain error: {e}")
                await self._send_ok(writer)

            elif path == "/api/reset-strategies" and method == "POST":
                self.ctx.strategy_cache.reset_all()
                self.ctx.ai_engine.reset()
                await self._send_ok(writer)

            elif path == "/api/ai-stats":
                stats = self.ctx.ai_engine.get_global_stats()
                intensity = self.ctx.get_ai_train_intensity()
                stats["train_intensity"] = intensity
                stats["train_profile"] = self.ctx.ai_train_profiles.get(
                    intensity,
                    self.ctx.ai_train_profiles["light"],
                )
                await self._send_json(writer, stats)

            elif path == "/api/performance-settings" and method == "GET":
                await self._send_json(writer, self._performance_payload())

            elif path == "/api/performance-settings" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 2048)
                    if not self._valid_performance_payload(req_data):
                        await self._send(
                            writer,
                            "400 Bad Request",
                            b'{"error":"invalid performance settings"}',
                            content_type="application/json",
                        )
                    else:
                        self.config_service.set_performance(req_data)
                        await self._send_json(writer, {"ok": True, "performance": self._performance_payload()})
                except Exception as e:
                    self.ctx.logger.error(f"Performance settings error: {e}")
                    await self._send(
                        writer,
                        "500 Internal Server Error",
                        b'{"error":"performance update failed"}',
                        content_type="application/json",
                    )

            elif path == "/api/network-flows":
                await self._send_json(writer, self.ctx.get_network_flows())

            elif path == "/api/network-exception" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 2048)
                    payload, ok = self.add_network_exception(req_data)
                    if ok:
                        await self._send_json(writer, payload)
                    else:
                        await self._send(
                            writer,
                            "400 Bad Request",
                            json.dumps(payload).encode(),
                            content_type="application/json",
                        )
                except Exception as e:
                    self.ctx.logger.error(f"Network exception error: {e}")
                    await self._send(
                        writer,
                        "500 Internal Server Error",
                        b'{"error":"network exception failed"}',
                        content_type="application/json",
                    )

            elif path == "/api/strategy-catalog":
                await self._send_json(
                    writer,
                    {
                        "default": "auto",
                        "strategies": list(self.ctx.strategy_names),
                        "options": ["auto"] + list(self.ctx.strategy_names),
                    },
                )

            elif path == "/api/site-strategy" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 2048)
                    site_name = req_data.get("site", "")
                    strategy = req_data.get("strategy", "")
                    valid_strategies = set(self.ctx.strategy_names)
                    if strategy != "auto" and strategy not in valid_strategies:
                        await self._send(
                            writer,
                            "400 Bad Request",
                            b'{"error":"invalid strategy"}',
                            content_type="application/json",
                        )
                    elif site_name not in config.get("sites", {}):
                        await self._send(
                            writer,
                            "400 Bad Request",
                            b'{"error":"invalid site"}',
                            content_type="application/json",
                        )
                    else:
                        self.config_service.set_site_strategy(site_name, strategy, valid_strategies)
                        await self._send_ok(writer)
                except Exception as e:
                    self.ctx.logger.error(f"Site strategy error: {e}")
                    await self._send(
                        writer,
                        "500 Internal Server Error",
                        b'{"error":"strategy update failed"}',
                        content_type="application/json",
                    )

            elif path == "/api/ai-train-intensity" and method == "GET":
                await self._send_json(
                    writer,
                    {
                        "intensity": self.ctx.get_ai_train_intensity(),
                        "profiles": self.ctx.ai_train_profiles,
                    },
                )

            elif path == "/api/ai-train-intensity" and method == "POST":
                try:
                    body_data = await self._read_json(reader, 1024)
                    new_intensity = body_data.get("intensity", "light")
                    if self.ctx.ai_engine.set_train_intensity(new_intensity):
                        self.ctx.set_ai_train_intensity(self.ctx.ai_engine.train_intensity)
                        self.ctx.logger.info(
                            f"[AI] Training intensity changed to: {self.ctx.get_ai_train_intensity()}"
                        )
                        await self._send_ok(writer)
                    else:
                        await self._send(
                            writer,
                            "400 Bad Request",
                            b'{"error":"invalid intensity"}',
                            content_type="application/json",
                        )
                except Exception as e:
                    self.ctx.logger.error(f"[AI] Set intensity error: {e}")
                    await self._send(
                        writer,
                        "500 Internal Server Error",
                        b'{"error":"server error"}',
                        content_type="application/json",
                    )

            elif path == "/api/ai-reset" and method == "POST":
                self.ctx.ai_engine.reset()
                await self._send_ok(writer)

            elif path == "/api/train-start" and method == "POST":
                if not self.ctx.training_state["active"]:
                    asyncio.create_task(self.ctx.train_all_sites())
                await self._send_ok(writer)

            elif path == "/api/train-status":
                await self._send_json(
                    writer,
                    {
                        "active": self.ctx.training_state["active"],
                        "completed": self.ctx.training_state["completed"],
                        "progress": self.ctx.training_state["progress"],
                        "results": {
                            s: {k: v for k, v in r.items() if k != "all_results"}
                            for s, r in self.ctx.training_state["results"].items()
                        },
                        "previous_strategies": self.ctx.training_state["previous_strategies"],
                    },
                )

            elif path == "/api/train-apply" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    site_name = req_data.get("site", "")
                    if site_name:
                        self.ctx.apply_training(site_name)
                except Exception as e:
                    self.ctx.logger.error(f"Train apply error: {e}")
                await self._send_ok(writer)

            elif path == "/api/train-revert" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    site_name = req_data.get("site", "")
                    if site_name:
                        self.ctx.revert_training(site_name)
                except Exception as e:
                    self.ctx.logger.error(f"Train revert error: {e}")
                await self._send_ok(writer)

            elif path == "/api/add-bypass" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    self.config_service.add_bypass(req_data.get("entry", ""))
                except Exception as e:
                    self.ctx.logger.error(f"Add bypass error: {e}")
                await self._send_ok(writer)

            elif path == "/api/remove-bypass" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    self.config_service.remove_bypass(req_data.get("entry", ""))
                except Exception as e:
                    self.ctx.logger.error(f"Remove bypass error: {e}")
                await self._send_ok(writer)

            elif path == "/api/clear-bypass" and method == "POST":
                try:
                    self.config_service.clear_bypass()
                except Exception as e:
                    self.ctx.logger.error(f"Clear bypass error: {e}")
                await self._send_ok(writer)

            elif path == "/api/load-preset" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    self.config_service.load_preset(req_data.get("preset", ""))
                except Exception as e:
                    self.ctx.logger.error(f"Load preset error: {e}")
                await self._send_ok(writer)

            elif path == "/api/get-autostart":
                await self._send_json(writer, {"autostart": self.ctx.get_autostart()})

            elif path == "/api/toggle-autostart" and method == "POST":
                current = self.ctx.get_autostart()
                self.ctx.set_autostart(not current)
                await self._send_ok(writer)

            elif path == "/api/privacy-setting" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    key = req_data.get("key", "")
                    value = bool(req_data.get("value", False))
                    if not self.config_service.set_privacy(key, value):
                        await self._send(
                            writer,
                            "400 Bad Request",
                            b'{"error":"invalid privacy key"}',
                            content_type="application/json",
                        )
                    else:
                        await self._send_json(
                            writer,
                            {"ok": True, "privacy": self.ctx.get_privacy_settings()},
                        )
                except Exception as e:
                    self.ctx.logger.error(f"Privacy setting error: {e}")
                    await self._send(
                        writer,
                        "500 Internal Server Error",
                        b'{"error":"privacy update failed"}',
                        content_type="application/json",
                    )

            elif path == "/api/test-site" and method == "POST":
                try:
                    req_data = await self._read_json(reader, 1024)
                    site_name = req_data.get("site", "")
                    if site_name and site_name in config.get("sites", {}):
                        asyncio.create_task(self.ctx.test_site_connection(site_name))
                except Exception as e:
                    self.ctx.logger.error(f"Test site error: {e}")
                await self._send_ok(writer)

            elif path == "/api/test-all" and method == "POST":
                for site_name in config.get("sites", {}):
                    if config["sites"][site_name].get("enabled", True):
                        asyncio.create_task(self.ctx.test_site_connection(site_name))
                await self._send_ok(writer)

            elif path == "/api/export-config":
                await self._send(
                    writer,
                    "200 OK",
                    json.dumps(config, indent=2, ensure_ascii=False).encode("utf-8"),
                    content_type="application/json",
                    headers=[("Content-Disposition", 'attachment; filename="cleannet_config.json"')],
                )

            elif path == "/api/diagnostics":
                await self._send(
                    writer,
                    "200 OK",
                    json.dumps(self.build_diagnostics_data(), indent=2, ensure_ascii=False).encode("utf-8"),
                    content_type="application/json",
                    headers=[("Content-Disposition", 'attachment; filename="cleannet_diagnostics.json"')],
                )

            elif path == "/api/import-config" and method == "POST":
                try:
                    new_config = await self._read_json(reader, 65536)
                    result = self.config_service.import_config(new_config)
                    if result.changed:
                        self._refresh_ips_if_needed(result)
                        await self._send_ok(writer)
                    else:
                        await self._send(
                            writer,
                            "400 Bad Request",
                            b'{"error":"Invalid config: missing sites"}',
                            content_type="application/json",
                        )
                except json.JSONDecodeError:
                    await self._send(
                        writer,
                        "400 Bad Request",
                        b'{"error":"Invalid JSON"}',
                        content_type="application/json",
                    )
                except Exception as e:
                    self.ctx.logger.error(f"Import config error: {e}")
                    await self._send(
                        writer,
                        "500 Internal Server Error",
                        b'{"error":"Import failed"}',
                        content_type="application/json",
                    )

            elif path == "/api/fix-uwp" and method == "POST":
                try:
                    bat_path = os.path.join(tempfile.gettempdir(), "cleannet_uwp_fix.bat")
                    with open(bat_path, "w", encoding="utf-8") as f:
                        f.write("@echo off\r\nCheckNetIsolation LoopbackExempt -a -p=S-1-15-2-1 >nul 2>&1\r\n")
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", bat_path, None, None, 1)
                    self.ctx.logger.info("[UWP] Loopback exemption requested (admin prompt)")
                    await self._send_ok(writer)
                except Exception as e:
                    self.ctx.logger.error(f"UWP fix error: {e}")
                    await self._send(
                        writer,
                        "500 Internal Server Error",
                        b'{"error":"UWP fix failed"}',
                        content_type="application/json",
                    )

            else:
                await self._send(writer, "404 Not Found", b"", include_length=False)
        except Exception:
            pass
        finally:
            _close_writer(writer)
