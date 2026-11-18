"""Small recommendation layer for strategy and site health."""

from __future__ import annotations

from typing import Any


def build_strategy_recommendations(
    sites: dict[str, Any],
    site_stats: dict[str, Any],
    ai_stats: dict[str, Any] | None,
    strategy_history: list[dict[str, Any]],
    active_connections: list[dict[str, Any]],
    verification: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []

    # Verification problems are the most actionable signal, so they go first.
    for site_name, snap in (verification or {}).items():
        if not snap or site_name not in sites:
            continue
        last = snap.get("last") or {}
        if snap.get("intercepted_recently") and last.get("status") != "verified":
            recommendations.append({
                "level": "critical",
                "site": site_name,
                "code": "dpi_intercepted",
                "title": "DPI interception detected",
                "detail": "The network answered with a certificate for another host. Run AI training "
                          "to find a strategy that passes verification.",
            })
        elif last.get("status") == "rejected":
            recommendations.append({
                "level": "warning",
                "site": site_name,
                "code": "browser_rejected",
                "title": "Browser rejected a bypassed connection",
                "detail": f"{last.get('strategy') or 'A strategy'} got a server reply but the handshake "
                          "failed in the browser; it is now counted as a failure.",
            })

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
                "code": "site_disabled",
                "title": "Site disabled",
                "detail": "Enable it before expecting traffic to use bypass strategies.",
            })
            continue

        if not site.get("ips"):
            recommendations.append({
                "level": "warning",
                "site": site_name,
                "code": "no_ip_pool",
                "title": "No pinned IP pool",
                "detail": "Run IP refresh or domain resolve so fallback routing has more choices.",
            })

        if connections >= 5 and total >= 5:
            failure_rate = failures / total
            if failure_rate >= 0.5:
                recommendations.append({
                    "level": "critical",
                    "site": site_name,
                    "code": "high_failure_rate",
                    "title": "High strategy failure rate",
                    "detail": f"{round(failure_rate * 100)}% of recent recorded attempts failed; run AI training for this site.",
                })

        if connections == 0:
            recommendations.append({
                "level": "info",
                "site": site_name,
                "code": "no_traffic",
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
                "code": "ai_warming_up",
                "title": "AI still warming up",
                "detail": "Collect at least 20 observations before trusting automatic ranking.",
            })
        elif accuracy and accuracy < 40:
            recommendations.append({
                "level": "warning",
                "site": "AI",
                "code": "low_first_try",
                "title": "Low first-try success",
                "detail": "The first strategy tried often fails; run AI training so live traffic starts with one that works.",
            })

    if len(active_connections) >= 20:
        recommendations.append({
            "level": "warning",
            "site": "runtime",
            "code": "many_connections",
            "title": "High live connection count",
            "detail": "Watch latency and per-site throttling during bursts.",
        })

    recent_failures = [item for item in strategy_history[-20:] if not item.get("success")]
    if len(recent_failures) >= 10:
        recommendations.append({
            "level": "warning",
            "site": "runtime",
            "code": "many_failures",
            "title": "Many recent strategy failures",
            "detail": "Use Test All or Train AI after network conditions stabilize.",
        })

    return recommendations[:8]

