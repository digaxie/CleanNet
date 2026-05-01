"""Static runtime settings and application path helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import sys
from typing import Any


@dataclass(frozen=True)
class AppPaths:
    script_dir: str
    app_file: str
    config_file: str
    strategy_cache_file: str
    stats_file: str
    ai_strategy_file: str


@dataclass(frozen=True)
class RuntimeSettings:
    local_host: str = "127.0.0.1"
    local_port: int = 8080
    web_port: int = 8888
    health_check_interval: int = 60
    ip_update_interval: int = 300
    low_latency_mode: bool = True
    background_training: bool = False
    ping_target_host: str = "1.1.1.1"
    strategy_success_timeout: float = 10.0
    strategy_failure_cooldown: int = 3600
    strategy_retest_interval: int = 7200
    strategy_save_interval: int = 60
    ai_save_interval: int = 120
    ai_min_samples: int = 5
    ai_exploration_rate: float = 0.15
    ai_decay_factor: float = 0.95
    ai_ring_buffer_size: int = 100
    ai_drift_check_interval: int = 60
    ai_self_train_interval: int = 1800
    ai_nn_hidden_size: int = 16
    ai_nn_input_size: int = 10
    ai_nn_learning_rate: float = 0.01
    ai_thompson_decay_interval: int = 200
    blocked_domain_ttl: int = 300
    site_max_concurrent: int = 24
    dns_privacy_cache_ttl: int = 900
    global_sni_strategy: str = "host_split"
    autostart_reg_name: str = "CleanNetDPIBypass"
    cdn_keyword_map: dict[str, str] = field(default_factory=lambda: {"discordapp": "discord"})


def build_app_paths(app_file: str) -> AppPaths:
    app_file = os.path.abspath(app_file)
    if getattr(sys, "frozen", False):
        app_file = os.path.abspath(sys.executable)
        exe_dir = os.path.dirname(app_file)
        parent_dir = os.path.dirname(exe_dir)
        if (
            os.path.basename(exe_dir).lower() == "dist"
            and (
                os.path.exists(os.path.join(parent_dir, "bypass_silent.pyw"))
                or os.path.isdir(os.path.join(parent_dir, "cleannet"))
            )
        ):
            runtime_dir = parent_dir
        else:
            runtime_dir = exe_dir
    else:
        runtime_dir = os.path.dirname(app_file)
    data_dir_override = os.environ.get("CLEANNET_DATA_DIR")
    script_dir = os.path.abspath(data_dir_override or runtime_dir)
    return AppPaths(
        script_dir=script_dir,
        app_file=app_file,
        config_file=os.path.join(script_dir, "config.json"),
        strategy_cache_file=os.path.join(script_dir, "strategy_cache.json"),
        stats_file=os.path.join(script_dir, "stats.json"),
        ai_strategy_file=os.path.join(script_dir, "ai_strategy.json"),
    )


def build_runtime_settings(config: dict[str, Any]) -> RuntimeSettings:
    performance = config.get("performance", {})
    low_latency_mode = bool(performance.get("low_latency_mode", True))
    return RuntimeSettings(
        local_port=config.get("proxy_port", 8080),
        web_port=config.get("dashboard_port", 8888),
        low_latency_mode=low_latency_mode,
        background_training=bool(performance.get("background_training", False)),
        health_check_interval=int(
            performance.get("health_check_interval", 120 if low_latency_mode else 60)
        ),
        ip_update_interval=int(
            performance.get("ip_update_interval", 1800 if low_latency_mode else 300)
        ),
        ping_target_host=str(performance.get("ping_target_host", "1.1.1.1") or "1.1.1.1"),
    )
