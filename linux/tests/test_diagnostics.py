import unittest

from cleannet.diagnostics import build_diagnostics_snapshot


class DiagnosticsTests(unittest.TestCase):
    def test_snapshot_contains_summaries_not_raw_runtime_objects(self):
        snapshot = build_diagnostics_snapshot(
            version="test",
            status="running",
            config={
                "proxy_port": 8080,
                "dashboard_port": 8888,
                "proxy_bypass": ["*.example"],
                "privacy": {"hide_dns": True, "hide_sni": False},
                "sites": {
                    "example": {
                        "enabled": True,
                        "domains": ["example.com"],
                        "ips": ["203.0.113.10"],
                        "strategy": "auto",
                    }
                },
            },
            stats={"connections": 1},
            site_stats={"example": {"connections": 1}},
            proxy={"enabled": True},
            performance={"low_latency_mode": True},
            network_diagnostics={"active_connection_count": 0},
            network_flows_summary={"flow_count": 0},
            ai_stats={"accuracy": 0},
            strategy_recommendations=[],
            active_connections=[],
            logs=["hello"],
        )

        self.assertEqual(snapshot["version"], "test")
        self.assertEqual(snapshot["config_summary"]["site_count"], 1)
        self.assertEqual(snapshot["site_summary"]["example"]["ip_count"], 1)
        self.assertEqual(snapshot["performance"]["low_latency_mode"], True)
        self.assertEqual(snapshot["network_flows_summary"]["flow_count"], 0)
        self.assertEqual(snapshot["recent_logs"], ["hello"])


if __name__ == "__main__":
    unittest.main()
