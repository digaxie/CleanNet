import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cleannet.app import CleanNetApp
from cleannet.bootstrap import create_app


def _write_runtime_files(
    root: str,
    *,
    site_name: str = "example",
    port: int = 9090,
    web_port: int = 9999,
    performance: dict | None = None,
):
    Path(root, "assets").mkdir(parents=True, exist_ok=True)
    Path(root, "assets", "dashboard.html").write_text(
        "<html><body>v__CLEANNET_VERSION__</body></html>",
        encoding="utf-8",
    )
    config = {
        "sites": {
            site_name: {
                "enabled": True,
                "domains": [f"{site_name}.test"],
                "dns_resolve": [f"{site_name}.test"],
                "ips": ["203.0.113.10"],
            }
        },
        "proxy_port": port,
        "dashboard_port": web_port,
        "proxy_bypass": [],
        "privacy": {"hide_dns": False, "hide_sni": False},
        "performance": performance
        or {
            "low_latency_mode": True,
            "background_training": False,
            "health_check_interval": 120,
            "ip_update_interval": 1800,
            "ping_target_host": "1.1.1.1",
        },
    }
    Path(root, "config.json").write_text(json.dumps(config), encoding="utf-8")
    return config


class BootstrapTests(unittest.TestCase):
    def test_create_app_builds_runtime_without_installing_handlers(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"DPI_BYPASS_NO_DISK_LOG": "1"}):
            _write_runtime_files(tmp)
            app_file = os.path.join(tmp, "bypass_silent.pyw")

            app = create_app(app_file, install_handlers=False)
            runtime = app.runtime

            self.assertIsInstance(app, CleanNetApp)
            self.assertIs(runtime.app, app)
            self.assertEqual(runtime.paths.app_file, os.path.abspath(app_file))
            self.assertEqual(runtime.paths.config_file, os.path.join(os.path.abspath(tmp), "config.json"))
            self.assertEqual(runtime.settings.local_port, 9090)
            self.assertEqual(runtime.settings.web_port, 9999)
            self.assertEqual(runtime.dashboard_html, "<html><body>v2.0</body></html>")
            self.assertEqual(app.ctx.local_host, "127.0.0.1")
            self.assertEqual(app.ctx.local_port, 9090)
            self.assertEqual(app.ctx.web_port, 9999)

    def test_contexts_share_runtime_state_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"DPI_BYPASS_NO_DISK_LOG": "1"}):
            _write_runtime_files(tmp)

            app = create_app(os.path.join(tmp, "bypass_silent.pyw"), install_handlers=False)
            runtime = app.runtime

            self.assertIs(runtime.proxy_engine.ctx.stats, runtime.state.stats)
            self.assertIs(runtime.dashboard_server.ctx.stats, runtime.state.stats)
            self.assertIs(runtime.dashboard_server.ctx.site_stats, runtime.state.site_stats)
            self.assertIs(runtime.dashboard_server.ctx.dashboard_log_handler, runtime.dashboard_handler)
            self.assertEqual(runtime.dashboard_server.ctx.script_dir, runtime.paths.script_dir)
            self.assertEqual(runtime.tray_manager.ctx.local_host, runtime.settings.local_host)
            self.assertEqual(runtime.tray_manager.ctx.web_port, runtime.settings.web_port)

    def test_reload_refreshes_state_and_dns_site_ips_reference(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"DPI_BYPASS_NO_DISK_LOG": "1"}):
            _write_runtime_files(tmp, site_name="old")
            app = create_app(os.path.join(tmp, "bypass_silent.pyw"), install_handlers=False)
            runtime = app.runtime
            old_site_ips = runtime.state.site_ips

            _write_runtime_files(tmp, site_name="new")
            result = runtime.reload_config_dynamically()

            self.assertTrue(result)
            self.assertEqual(runtime.state.site_names, ["new"])
            self.assertIsNot(runtime.state.site_ips, old_site_ips)
            self.assertIs(runtime.dns_resolver.ctx.site_ips, runtime.state.site_ips)
            self.assertEqual(runtime.find_site_for_host("new.test"), "new")
            self.assertIsNone(runtime.find_site_for_host("old.test"))

    def test_reload_refreshes_performance_contexts(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"DPI_BYPASS_NO_DISK_LOG": "1"}):
            _write_runtime_files(tmp)
            app = create_app(os.path.join(tmp, "bypass_silent.pyw"), install_handlers=False)
            runtime = app.runtime

            _write_runtime_files(
                tmp,
                performance={
                    "low_latency_mode": False,
                    "background_training": True,
                    "health_check_interval": 300,
                    "ip_update_interval": 900,
                    "ping_target_host": "8.8.8.8",
                },
            )
            runtime.reload_config_dynamically()

            self.assertFalse(runtime.settings.low_latency_mode)
            self.assertTrue(runtime.settings.background_training)
            self.assertEqual(runtime.background_tasks.ctx.health_check_interval, 300)
            self.assertEqual(runtime.background_tasks.ctx.ip_update_interval, 900)
            self.assertEqual(runtime.background_tasks.ctx.ping_target_host, "8.8.8.8")
            self.assertTrue(runtime.training_manager.ctx.get_background_training_enabled())
            self.assertEqual(runtime.dashboard_server.ctx.get_performance_settings()["ping_target_host"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
