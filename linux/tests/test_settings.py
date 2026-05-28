import os
import tempfile
import unittest
from unittest.mock import patch

from cleannet.settings import RuntimeSettings, build_app_paths, build_runtime_settings


class SettingsTests(unittest.TestCase):
    def test_build_app_paths_separates_source_and_xdg_data(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as xdg_tmp:
            app_file = os.path.join(source_tmp, "cleannet", "__main__.py")
            os.makedirs(os.path.dirname(app_file))

            with patch.dict(os.environ, {"XDG_DATA_HOME": xdg_tmp}, clear=True):
                paths = build_app_paths(app_file)

            expected_data = os.path.join(os.path.abspath(xdg_tmp), "cleannet")
            self.assertEqual(paths.source_dir, os.path.abspath(source_tmp))
            self.assertEqual(paths.data_dir, expected_data)
            self.assertEqual(paths.script_dir, expected_data)
            self.assertEqual(paths.app_file, os.path.abspath(app_file))
            self.assertEqual(paths.config_file, os.path.join(expected_data, "config.json"))
            self.assertEqual(paths.strategy_cache_file, os.path.join(expected_data, "strategy_cache.json"))
            self.assertEqual(paths.stats_file, os.path.join(expected_data, "stats.json"))
            self.assertEqual(paths.ai_strategy_file, os.path.join(expected_data, "ai_strategy.json"))

    def test_build_app_paths_allows_data_dir_override(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as data_tmp:
            app_file = os.path.join(source_tmp, "cleannet", "__main__.py")
            os.makedirs(os.path.dirname(app_file))

            with patch.dict(os.environ, {"CLEANNET_DATA_DIR": data_tmp}, clear=True):
                paths = build_app_paths(app_file)

            self.assertEqual(paths.source_dir, os.path.abspath(source_tmp))
            self.assertEqual(paths.data_dir, os.path.abspath(data_tmp))
            self.assertEqual(paths.config_file, os.path.join(os.path.abspath(data_tmp), "config.json"))

    def test_build_app_paths_default_xdg_location(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as home_tmp:
            app_file = os.path.join(source_tmp, "cleannet", "__main__.py")
            os.makedirs(os.path.dirname(app_file))

            with patch.dict(os.environ, {"HOME": home_tmp}, clear=True):
                paths = build_app_paths(app_file)

            expected = os.path.join(home_tmp, ".local", "share", "cleannet")
            self.assertEqual(paths.data_dir, os.path.abspath(expected))

    def test_build_runtime_settings_uses_config_ports_and_static_defaults(self):
        settings = build_runtime_settings({
            "proxy_port": 9090,
            "dashboard_port": 9999,
            "performance": {
                "low_latency_mode": False,
                "background_training": True,
                "health_check_interval": 60,
                "ip_update_interval": 300,
                "ping_target_host": "8.8.8.8",
            },
        })

        self.assertEqual(settings.local_host, "127.0.0.1")
        self.assertEqual(settings.local_port, 9090)
        self.assertEqual(settings.web_port, 9999)
        self.assertEqual(settings.health_check_interval, 60)
        self.assertEqual(settings.ip_update_interval, 300)
        self.assertFalse(settings.low_latency_mode)
        self.assertTrue(settings.background_training)
        self.assertEqual(settings.ping_target_host, "8.8.8.8")
        self.assertEqual(settings.strategy_success_timeout, 10.0)
        self.assertEqual(settings.ai_min_samples, 5)
        self.assertEqual(settings.cdn_keyword_map, {"discordapp": "discord"})

    def test_runtime_settings_port_defaults_match_existing_config_defaults(self):
        settings = build_runtime_settings({})

        self.assertIsInstance(settings, RuntimeSettings)
        self.assertEqual(settings.local_port, 8080)
        self.assertEqual(settings.web_port, 8888)
        self.assertTrue(settings.low_latency_mode)
        self.assertFalse(settings.background_training)
        self.assertEqual(settings.health_check_interval, 120)
        self.assertEqual(settings.ip_update_interval, 1800)
        self.assertEqual(settings.ping_target_host, "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
