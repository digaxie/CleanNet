"""Small recommendation layer for strategy and site health."""

from __future__ import annotations

from typing import Any


def build_strategy_recommendations(
    sites: dict[str, Any],
    site_stats: dict[str, Any],
    ai_stats: dict[str, Any] | None,
    strategy_history: list[dict[str, Any]],
    active_connections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []

    for site_name, site in sites.items():
        stats = site_stats.get(site_name, {})
        connections = int(stats.get("connections", 0) or 0)
        successes = int(stats.get("successes", 0) or 0)
        failures = int(stats.get("failures", 0) or 0)
        total = successes + failures

        if not site.get("enabled", True):
            recommendations.append({
                "level": "info",
                "site": site_name,
                "title": "Site disabled",
                "detail": "Enable it before expecting traffic to use bypass strategies.",
            })
            continue

        if not site.get("ips"):
            recommendations.append({
                "level": "warning",
                "site": site_name,
                "title": "No pinned IP pool",
                "detail": "Run IP refresh or domain resolve so fallback routing has more choices.",
            })

        if connections >= 5 and total >= 5:
            failure_rate = failures / total
            if failure_rate >= 0.5:
                recommendations.append({
                    "level": "critical",
                    "site": site_name,
                    "title": "High strategy failure rate",
                    "detail": f"{round(failure_rate * 100)}% of recent recorded attempts failed; run AI training for this site.",
                })

        if connections == 0:
            recommendations.append({
                "level": "info",
                "site": site_name,
                "title": "No traffic observed",
                "detail": "Open the target site once to let CleanNet learn a baseline.",
            })

    if ai_stats:
        total_obs = int(ai_stats.get("total_observations", 0) or 0)
        accuracy = float(ai_stats.get("accuracy", 0) or 0)
        if total_obs < 20:
            recommendations.append({
                "level": "info",
                "site": "AI",
                "title": "AI still warming up",
                "detail": "Collect at least 20 observations before trusting automatic ranking.",
            })
        elif accuracy and accuracy < 40:
            recommendations.append({
                "level": "warning",
                "site": "AI",
                "title": "Low prediction accuracy",
                "detail": "Reset or retrain strategies if this stays low after fresh traffic.",
            })

    if len(active_connections) >= 20:
        recommendations.append({
            "level": "warning",
            "site": "runtime",
            "title": "High live connection count",
            "detail": "Watch latency and per-site throttling during bursts.",
        })

    recent_failures = [item for item in strategy_history[-20:] if not item.get("success")]
    if len(recent_failures) >= 10:
        recommendations.append({
            "level": "warning",
            "site": "runtime",
            "title": "Many recent strategy failures",
            "detail": "Use Test All or Train AI after network conditions stabilize.",
        })

    return recommendations[:8]

