"""Bootstrap CleanNet runtime dependencies and create the app service."""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Any

from . import __version__
from .ai_engine import AdaptiveStrategyEngine, StrategyCache, parse_iso as _parse_iso
from .app import CleanNetApp, CleanNetAppContext
from .background_tasks import BackgroundTaskContext, BackgroundTaskManager
from .config import (
    build_lists_from_config,
    load_config_file,
    save_config_file,
)
from .config_defaults import ALWAYS_BYPASS, BYPASS_PRESETS
from .dashboard import DashboardRuntimeContext, DashboardServer, load_dashboard_html
from .dns_resolver import (
    DOH_BOOTSTRAP_MAP,
    DnsResolver,
    DnsResolverContext,
    is_ip_literal,
)
from .logging_setup import setup_logging
from .network_monitor import NetworkMonitor
from .proxy_engine import ProxyEngine, ProxyRuntimeContext
from .runtime import RuntimeState
from .settings import AppPaths, RuntimeSettings, build_app_paths, build_runtime_settings
from .stats import load_stats_file, save_stats_file
from .strategies import StrategyRuntimeContext, build_strategy_funcs
from .strategy_catalog import AI_TRAIN_PROFILES, STRATEGY_ORDER
from .training import TrainingManager, TrainingRuntimeContext
from .tray import TRAY_AVAILABLE, TrayManager, TrayRuntimeContext
from .windows_integration import (
    ensure_system_proxy_enabled,
    get_autostart as _win_get_autostart,
    recover_orphaned_proxy,
    set_autostart as _win_set_autostart,
    set_system_proxy,
)


class CleanNetRuntime:
    """Owns the shared runtime graph used by CleanNet services."""

    def __init__(self, app_file: str):
        self.paths: AppPaths = build_app_paths(app_file)
        self.logging_setup = setup_logging(self.paths.script_dir, reset_handlers=True)
        self.log_file = self.logging_setup.log_file
        self.logger = self.logging_setup.logger
        self.dashboard_handler = self.logging_setup.dashboard_handler
        self.hash_host = self.logging_setup.hash_host

        self.state = RuntimeState.from_config(self.load_config(), build_lists_from_config)
        self.settings: RuntimeSettings = build_runtime_settings(self.state.config)
        self.app: CleanNetApp | None = None

        self.load_stats()
        self.dns_resolver = DnsResolver(self.build_dns_context())
        self.strategy_funcs = build_strategy_funcs(
            StrategyRuntimeContext(record_fragments=self.record_strategy_fragments)
        )
        self.strategy_cache = StrategyCache(
            self.paths.strategy_cache_file,
            logger=self.logger,
            config_provider=lambda: self.state.config,
            strategy_names=self.strategy_funcs.keys(),
            ai_engine_provider=lambda: self.ai_engine,
            save_interval=self.settings.strategy_save_interval,
            failure_cooldown=self.settings.strategy_failure_cooldown,
        )
        self.ai_engine = AdaptiveStrategyEngine(
            self.paths.ai_strategy_file,
            logger=self.logger,
            train_intensity=self.state.ai_train_intensity,
            save_interval=self.settings.ai_save_interval,
            min_samples=self.settings.ai_min_samples,
            decay_factor=self.settings.ai_decay_factor,
            ring_buffer_size=self.settings.ai_ring_buffer_size,
            drift_check_interval=self.settings.ai_drift_check_interval,
            nn_hidden_size=self.settings.ai_nn_hidden_size,
            nn_input_size=self.settings.ai_nn_input_size,
            nn_learning_rate=self.settings.ai_nn_learning_rate,
            thompson_decay_interval=self.settings.ai_thompson_decay_interval,
        )
        self.state.set_ai_train_intensity(self.ai_engine.train_intensity)

        self.background_tasks = BackgroundTaskManager(self.build_background_context())
        self.training_manager = TrainingManager(self.build_training_context())
        self.proxy_engine = ProxyEngine(self.build_proxy_context())
        self.network_monitor = NetworkMonitor()
        self.dashboard_html = load_dashboard_html(self.paths.script_dir, __version__)
        self.dashboard_server = DashboardServer(self.build_dashboard_context())
        self.tray_manager = TrayManager(self.build_tray_context())

    def load_config(self) -> dict[str, Any]:
        return load_config_file(self.paths.config_file, logger=self.logger)

    def save_config(self) -> None:
        save_config_file(self.paths.config_file, self.state.config)

    def reload_config_dynamically(self) -> bool:
        self.state.apply_config(self.load_config(), build_lists_from_config)
        self.settings = build_runtime_settings(self.state.config)
        self.refresh_runtime_contexts()
        if self.get_running():
            self.set_proxy(True, self.settings.local_host, self.settings.local_port)
        self.logger.info(
            f"Config reloaded: {len(self.state.site_names)} sites, "
            f"{len(self.state.config.get('proxy_bypass', []))} bypass entries"
        )
        return True

    def refresh_runtime_contexts(self) -> None:
        self.dns_resolver.ctx.site_ips = self.state.site_ips
        self.dns_resolver.ctx.privacy_cache_ttl = self.settings.dns_privacy_cache_ttl

        background_ctx = self.background_tasks.ctx
        background_ctx.local_host = self.settings.local_host
        background_ctx.local_port = self.settings.local_port
        background_ctx.health_check_interval = self.settings.health_check_interval
        background_ctx.ip_update_interval = self.settings.ip_update_interval
        background_ctx.ping_target_host = self.settings.ping_target_host
        background_ctx.strategy_retest_interval = self.settings.strategy_retest_interval

        proxy_ctx = self.proxy_engine.ctx
        proxy_ctx.global_sni_strategy = self.settings.global_sni_strategy
        proxy_ctx.strategy_success_timeout = self.settings.strategy_success_timeout
        proxy_ctx.blocked_domain_ttl = self.settings.blocked_domain_ttl
        proxy_ctx.site_max_concurrent = self.settings.site_max_concurrent

        dashboard_ctx = self.dashboard_server.ctx
        dashboard_ctx.local_host = self.settings.local_host
        dashboard_ctx.local_port = self.settings.local_port

        tray_ctx = self.tray_manager.ctx
        tray_ctx.local_host = self.settings.local_host
        tray_ctx.web_port = self.settings.web_port

        if self.app:
            self.app.ctx.local_host = self.settings.local_host
            self.app.ctx.local_port = self.settings.local_port
            self.app.ctx.web_port = self.settings.web_port

    def load_stats(self) -> None:
        stats, site_stats = load_stats_file(
            self.paths.stats_file,
            {"global": self.state.stats, "sites": self.state.site_stats},
            logger=self.logger,
        )
        self.state.set_stats(stats, site_stats)

    def save_stats(self) -> None:
        save_stats_file(self.paths.stats_file, self.state.stats, self.state.site_stats, logger=self.logger)

    def get_running(self) -> bool:
        return bool(self.app and self.app.running)

    def get_status(self) -> str:
        return self.app.status if self.app else "stopped"

    def get_start_time(self) -> float | None:
        return self.app.start_time if self.app else None

    def get_loop(self):
        return self.app.loop if self.app else None

    def get_shutdown_event(self):
        return self.app.shutdown_event if self.app else None

    def set_running(self, value: bool) -> None:
        if self.app:
            self.app.set_running(value)

    def release_instance_lock(self) -> None:
        if self.app:
            self.app.release_instance_lock()

    def get_active_connections(self) -> list[dict[str, Any]]:
        return self.state.active_connections()

    def get_performance_settings(self) -> dict[str, Any]:
        performance = dict(self.state.config.get("performance", {}))
        performance.setdefault("low_latency_mode", True)
        performance.setdefault("background_training", False)
        performance.setdefault("health_check_interval", 120)
        performance.setdefault("ip_update_interval", 1800)
        performance.setdefault("ping_target_host", "1.1.1.1")
        performance["effective"] = {
            "low_latency_mode": self.settings.low_latency_mode,
            "background_training": self.settings.background_training,
            "health_check_interval": self.settings.health_check_interval,
            "ip_update_interval": self.settings.ip_update_interval,
            "ping_target_host": self.settings.ping_target_host,
        }
        return performance

    def get_network_flows(self) -> dict[str, Any]:
        return self.network_monitor.snapshot(
            self.state.config.get("proxy_bypass", []),
            ALWAYS_BYPASS,
        )

    def find_site_for_host(self, host: str) -> str | None:
        return self.state.find_site_for_host(host, self.settings.cdn_keyword_map)

    def is_main_domain(self, host: str, site_name: str) -> bool:
        return self.state.is_main_domain(host, site_name)

    def get_bypass_ip(self, host: str) -> str | None:
        return self.state.get_bypass_ip(host, self.settings.cdn_keyword_map)

    def get_domain_ips(self, host: str) -> list[str]:
        return self.state.get_domain_ips(host)

    def get_site_ips(self, host: str) -> list[str]:
        return self.state.get_site_ips(host, self.settings.cdn_keyword_map)

    def set_proxy(self, enable: bool, host: str = "127.0.0.1", port: int = 8080):
        return set_system_proxy(
            enable,
            host,
            port,
            ALWAYS_BYPASS,
            self.state.config.get("proxy_bypass", []),
            app_dir=self.paths.script_dir,
            logger=self.logger,
        )

    def ensure_proxy(self):
        return ensure_system_proxy_enabled(
            self.settings.local_host,
            self.settings.local_port,
            ALWAYS_BYPASS,
            self.state.config.get("proxy_bypass", []),
            logger=self.logger,
        )

    def get_autostart(self) -> bool:
        return _win_get_autostart(self.settings.autostart_reg_name)

    def set_autostart(self, enable: bool):
        return _win_set_autostart(
            enable,
            self.settings.autostart_reg_name,
            self.paths.app_file,
            sys.executable,
            logger=self.logger,
        )

    def notify(self, title: str, message: str) -> None:
        self.logger.info(f"[NOTIFY] {title}: {message}")

    def set_bypass_ips(self, ips: list[str]) -> None:
        self.state.set_bypass_ips(ips)

    def build_dns_context(self) -> DnsResolverContext:
        return DnsResolverContext(
            logger=self.logger,
            domain_ips=self.state.domain_ips,
            site_ips=self.state.site_ips,
            privacy_cache=self.state.dns_privacy_cache,
            stats=self.state.stats,
            get_site_dns=lambda: self.state.site_dns,
            set_bypass_ips=self.set_bypass_ips,
            hash_host=self.hash_host,
            privacy_cache_ttl=self.settings.dns_privacy_cache_ttl,
        )

    def resolve_domain_doh(self, domain: str, timeout: int = 5) -> list[str]:
        return self.dns_resolver.resolve_domain_doh(domain, timeout=timeout)

    async def resolve_domain_privately(self, domain: str) -> list[str]:
        return await self.dns_resolver.resolve_domain_privately(domain)

    async def resolve_bypass_ips(self) -> bool:
        return await self.dns_resolver.resolve_bypass_ips()

    def record_privacy_event(
        self,
        host: str,
        site_name: str | None = None,
        dns_status: str = "unknown",
        dns_detail: str = "",
        sni_status: str = "unknown",
        sni_detail: str = "",
    ) -> None:
        event = {
            "host": host,
            "dns_status": dns_status,
            "dns_detail": dns_detail,
            "sni_status": sni_status,
            "sni_detail": sni_detail,
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        if site_name:
            self.state.site_privacy_state[site_name] = dict(event)

        dns_txt = dns_status
        if dns_detail:
            dns_txt += f" ({dns_detail})"
        sni_txt = sni_status
        if sni_detail:
            sni_txt += f" ({sni_detail})"
        self.logger.info(f"[PRIVACY] {host} DNS={dns_txt} | SNI={sni_txt}")

    def record_strategy_fragments(self, count: int) -> None:
        self.state.record_strategy_fragments(count)

    def set_ping_ms(self, value: int) -> None:
        self.state.set_ping_ms(value)

    def build_background_context(self) -> BackgroundTaskContext:
        return BackgroundTaskContext(
            logger=self.logger,
            get_config=lambda: self.state.config,
            get_running=self.get_running,
            set_ping_ms=self.set_ping_ms,
            ping_history=self.state.ping_history,
            test_results=self.state.test_results,
            get_bypass_ips=lambda: self.state.bypass_ips,
            get_bypass_domains=lambda: self.state.bypass_domains,
            local_host=self.settings.local_host,
            local_port=self.settings.local_port,
            health_check_interval=self.settings.health_check_interval,
            ip_update_interval=self.settings.ip_update_interval,
            ping_target_host=self.settings.ping_target_host,
            strategy_retest_interval=self.settings.strategy_retest_interval,
            resolve_bypass_ips=self.resolve_bypass_ips,
            notify=self.notify,
            strategy_cache=self.strategy_cache,
            save_stats=self.save_stats,
            ensure_proxy_enabled=self.ensure_proxy,
            parse_iso=_parse_iso,
            now_iso=lambda: datetime.now().isoformat(timespec="seconds"),
        )

    def build_training_context(self) -> TrainingRuntimeContext:
        return TrainingRuntimeContext(
            logger=self.logger,
            get_config=lambda: self.state.config,
            get_running=self.get_running,
            get_ai_train_intensity=lambda: self.state.ai_train_intensity,
            get_background_training_enabled=lambda: self.settings.background_training,
            training_state=self.state.training_state,
            self_train_state=self.state.self_train_state,
            ai_engine=self.ai_engine,
            strategy_cache=self.strategy_cache,
            strategy_funcs=self.strategy_funcs,
            strategy_order=STRATEGY_ORDER,
            ai_train_profiles=AI_TRAIN_PROFILES,
            ai_min_samples=self.settings.ai_min_samples,
            get_bypass_ip=self.get_bypass_ip,
            resolve_domain_doh=self.resolve_domain_doh,
            hash_host=self.hash_host,
        )

    def build_proxy_context(self) -> ProxyRuntimeContext:
        return ProxyRuntimeContext(
            logger=self.logger,
            stats=self.state.stats,
            site_stats=self.state.site_stats,
            strategy_history=self.state.strategy_history,
            domain_ips=self.state.domain_ips,
            blocked_domains=self.state.blocked_domains,
            site_semaphores=self.state.site_semaphores,
            connection_tracker=self.state.connection_tracker,
            strategy_cache=self.strategy_cache,
            ai_engine=self.ai_engine,
            strategy_funcs=self.strategy_funcs,
            direct_strategy=self.strategy_funcs["direct"],
            get_privacy_settings=self.state.get_privacy_settings,
            resolve_domain_privately=self.resolve_domain_privately,
            resolve_domain_doh=self.resolve_domain_doh,
            is_ip_literal=is_ip_literal,
            hash_host=self.hash_host,
            find_site_for_host=self.find_site_for_host,
            is_main_domain=self.is_main_domain,
            get_bypass_ip=self.get_bypass_ip,
            get_domain_ips=self.get_domain_ips,
            get_site_ips=self.get_site_ips,
            record_privacy_event=self.record_privacy_event,
            doh_bootstrap_map=DOH_BOOTSTRAP_MAP,
            global_sni_strategy=self.settings.global_sni_strategy,
            strategy_success_timeout=self.settings.strategy_success_timeout,
            blocked_domain_ttl=self.settings.blocked_domain_ttl,
            site_max_concurrent=self.settings.site_max_concurrent,
        )

    def set_ai_train_intensity(self, value: str) -> None:
        self.state.set_ai_train_intensity(value)

    def build_dashboard_context(self) -> DashboardRuntimeContext:
        return DashboardRuntimeContext(
            version=__version__,
            dashboard_html=self.dashboard_html,
            logger=self.logger,
            get_config=lambda: self.state.config,
            save_config=self.save_config,
            reload_config=self.reload_config_dynamically,
            resolve_bypass_ips=self.resolve_bypass_ips,
            resolve_domain_doh=self.resolve_domain_doh,
            strategy_cache=self.strategy_cache,
            ai_engine=self.ai_engine,
            get_ai_train_intensity=lambda: self.state.ai_train_intensity,
            set_ai_train_intensity=self.set_ai_train_intensity,
            ai_train_profiles=AI_TRAIN_PROFILES,
            training_state=self.state.training_state,
            self_train_state=self.state.self_train_state,
            train_all_sites=self.training_manager.train_all_sites,
            apply_training=self.training_manager.apply_training,
            revert_training=self.training_manager.revert_training,
            always_bypass=ALWAYS_BYPASS,
            bypass_presets=BYPASS_PRESETS,
            get_autostart=self.get_autostart,
            set_autostart=self.set_autostart,
            get_privacy_settings=self.state.get_privacy_settings,
            get_performance_settings=self.get_performance_settings,
            get_network_flows=self.get_network_flows,
            test_site_connection=self.background_tasks.test_site_connection,
            get_running=self.get_running,
            get_status=self.get_status,
            get_ping_ms=lambda: self.state.ping_ms,
            get_start_time=self.get_start_time,
            get_bypass_ips=lambda: self.state.bypass_ips,
            get_active_connections=self.get_active_connections,
            dashboard_log_handler=self.dashboard_handler,
            stats=self.state.stats,
            site_stats=self.state.site_stats,
            strategy_history=self.state.strategy_history,
            test_results=self.state.test_results,
            site_privacy_state=self.state.site_privacy_state,
            script_dir=self.paths.script_dir,
            local_host=self.settings.local_host,
            local_port=self.settings.local_port,
            strategy_names=list(STRATEGY_ORDER),
        )

    def force_save_runtime_state(self) -> None:
        self.strategy_cache.force_save()
        self.ai_engine.force_save()

    def build_tray_context(self) -> TrayRuntimeContext:
        return TrayRuntimeContext(
            version=__version__,
            logger=self.logger,
            local_host=self.settings.local_host,
            web_port=self.settings.web_port,
            log_file=self.log_file,
            app_file=self.paths.app_file,
            python_executable=sys.executable,
            asset_dir=self.paths.script_dir,
            get_status=self.get_status,
            get_ping_ms=lambda: self.state.ping_ms,
            get_loop=self.get_loop,
            get_shutdown_event=self.get_shutdown_event,
            set_running=self.set_running,
            force_save=self.force_save_runtime_state,
            set_proxy_enabled=lambda enabled: self.set_proxy(
                enabled,
                self.settings.local_host,
                self.settings.local_port,
            ),
            release_instance_lock=self.release_instance_lock,
            resolve_bypass_ips=self.resolve_bypass_ips,
        )

    def build_app_context(self) -> CleanNetAppContext:
        return CleanNetAppContext(
            logger=self.logger,
            version=__version__,
            get_site_names=lambda: self.state.site_names,
            local_host=self.settings.local_host,
            local_port=self.settings.local_port,
            web_port=self.settings.web_port,
            proxy_engine=self.proxy_engine,
            dashboard_server=self.dashboard_server,
            background_tasks=self.background_tasks,
            training_manager=self.training_manager,
            tray_available=TRAY_AVAILABLE,
            tray_manager=self.tray_manager,
            set_proxy_enabled=lambda enabled: self.set_proxy(
                enabled,
                self.settings.local_host,
                self.settings.local_port,
            ),
            ensure_proxy_enabled=self.ensure_proxy,
            force_save=self.force_save_runtime_state,
            save_stats=self.save_stats,
            recover_proxy=lambda: recover_orphaned_proxy(
                self.settings.local_host,
                self.settings.local_port,
                self.paths.script_dir,
                logger=self.logger,
            ),
        )

    def create_app(self) -> CleanNetApp:
        self.app = CleanNetApp(self.build_app_context())
        self.app.runtime = self
        return self.app


def create_app(app_file: str, install_handlers: bool = True) -> CleanNetApp:
    runtime = CleanNetRuntime(app_file)
    app = runtime.create_app()
    if install_handlers:
        app.install_exit_handlers()
    return app
