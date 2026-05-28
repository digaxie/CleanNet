"""Diagnostic export helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def build_diagnostics_snapshot(
    *,
    version: str,
    status: str,
    config: dict[str, Any],
    stats: dict[str, Any],
    site_stats: dict[str, Any],
    proxy: dict[str, Any],
    performance: dict[str, Any],
    network_diagnostics: dict[str, Any],
    network_flows_summary: dict[str, Any],
    ai_stats: dict[str, Any],
    strategy_recommendations: list[dict[str, Any]],
    active_connections: list[dict[str, Any]],
    logs: list[str],
) -> dict[str, Any]:
    sites = config.get("sites", {})
    return {
        "version": version,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "status": status,
        "config_summary": {
            "proxy_port": config.get("proxy_port"),
            "dashboard_port": config.get("dashboard_port"),
            "site_count": len(sites),
            "enabled_site_count": sum(1 for site in sites.values() if site.get("enabled", True)),
            "proxy_bypass_count": len(config.get("proxy_bypass", [])),
            "privacy": config.get("privacy", {}),
            "performance": config.get("performance", {}),
        },
        "site_summary": {
            name: {
                "enabled": site.get("enabled", True),
                "domain_count": len(site.get("domains", [])),
                "ip_count": len(site.get("ips", [])),
                "strategy": site.get("strategy", "auto"),
            }
            for name, site in sites.items()
        },
        "stats": stats,
        "site_stats": site_stats,
        "proxy": proxy,
        "performance": performance,
        "network_diagnostics": network_diagnostics,
        "network_flows_summary": network_flows_summary,
        "ai_stats": ai_stats,
        "strategy_recommendations": strategy_recommendations,
        "active_connections": active_connections[:25],
        "recent_logs": logs[-80:],
    }
