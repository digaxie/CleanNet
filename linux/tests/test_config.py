import json
import os
import tempfile
import unittest

from cleannet.config import (
    DEFAULT_CONFIG,
    build_lists_from_config,
    default_config,
    load_config_file,
    save_config_file,
    validate_config,
)
from cleannet.config_defaults import (
    ALWAYS_BYPASS,
    BYPASS_PRESETS,
    DEFAULT_CONFIG as SOURCE_DEFAULT_CONFIG,
    get_bypass_preset_options,
)


class ConfigTests(unittest.TestCase):
    def test_default_constants_are_exported_from_single_source(self):
        self.assertIs(DEFAULT_CONFIG, SOURCE_DEFAULT_CONFIG)
        self.assertIn("discord", default_config()["sites"])
        self.assertIn("localhost", ALWAYS_BYPASS)
        self.assertIn("gaming", BYPASS_PRESETS)
        self.assertIn("*.riotgames.com", BYPASS_PRESETS["gaming"])

    def test_bypass_preset_options_include_metadata_and_addable_counts(self):
        options = get_bypass_preset_options(ALWAYS_BYPASS)
        by_name = {item["name"]: item for item in options}

        self.assertIn("streaming", by_name)
        self.assertIn("social", by_name)
        self.assertGreater(by_name["streaming"]["entry_count"], 3)
        self.assertGreater(by_name["cdn"]["built_in_count"], 0)
        self.assertGreater(by_name["cdn"]["addable_count"], 0)

    def test_validate_fills_required_defaults(self):
        config, errors = validate_config({"sites": {}})

        self.assertEqual(config["proxy_port"], 8080)
        self.assertEqual(config["dashboard_port"], 8888)
        self.assertEqual(config["proxy_bypass"], [])
        self.assertFalse(config["privacy"]["hide_dns"])
        self.assertFalse(config["privacy"]["hide_sni"])
        self.assertTrue(config["performance"]["low_latency_mode"])
        self.assertFalse(config["performance"]["background_training"])
        self.assertEqual(config["performance"]["ip_update_interval"], 1800)
        self.assertTrue(config["setup"]["onboarding_completed"])
        self.assertGreaterEqual(len(errors), 4)

    def test_default_config_requires_first_run_onboarding(self):
        self.assertFalse(default_config()["setup"]["onboarding_completed"])

    def test_validate_removes_obsolete_vpn_keys(self):
        config, errors = validate_config({
            "vpn": {"enabled": True},
            "sites": {
                "example": {
                    "domains": ["example.com"],
                    "vpn": True,
                }
            },
            "proxy_port": 8080,
            "dashboard_port": 8888,
            "proxy_bypass": [],
            "privacy": {"hide_dns": False, "hide_sni": False},
        })

        self.assertNotIn("vpn", config)
        self.assertNotIn("vpn", config["sites"]["example"])
        self.assertTrue(any("obsolete" in item for item in errors))

    def test_build_lists_ignores_disabled_sites(self):
        config = default_config()
        config["sites"]["disabled"] = {
            "enabled": False,
            "domains": ["disabled.example"],
            "dns_resolve": ["disabled.example"],
            "ips": ["203.0.113.1"],
        }

        domains, ips, domain_to_site, site_ips, site_dns = build_lists_from_config(config)

        self.assertIn("discord.com", domains)
        self.assertNotIn("disabled.example", domains)
        self.assertNotIn("203.0.113.1", ips)
        self.assertEqual(domain_to_site["discord.com"], "discord")
        self.assertIn("discord", site_ips)
        self.assertIn("discord", site_dns)


class ConfigFileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "config.json")

    def tearDown(self):
        self._tmp.cleanup()

    def test_load_accepts_utf8_bom(self):
        # Regression: a config saved by Notepad/PowerShell 5 (UTF-8 with BOM) was
        # rejected as invalid JSON and silently replaced by defaults.
        with open(self.path, "w", encoding="utf-8-sig") as f:
            json.dump({"sites": {"mine": {"domains": ["mine.test"]}}}, f)

        config = load_config_file(self.path)

        self.assertIn("mine", config["sites"])

    def test_load_keeps_copy_of_corrupt_config(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write('{"sites": {"mine": ')

        config = load_config_file(self.path)

        self.assertIn("discord", config["sites"])
        backups = [name for name in os.listdir(self._tmp.name) if name.startswith("config.json.corrupt-")]
        self.assertEqual(len(backups), 1)

    def test_save_is_atomic_and_leaves_no_temp_file(self):
        save_config_file(self.path, {"sites": {}})
        save_config_file(self.path, {"sites": {"a": {"domains": ["a.test"]}}})

        with open(self.path, encoding="utf-8") as f:
            self.assertIn("a", json.load(f)["sites"])
        self.assertEqual(os.listdir(self._tmp.name), ["config.json"])

    def test_validate_rejects_bool_and_out_of_range_ports(self):
        config, _errors = validate_config({"sites": {}, "proxy_port": True, "dashboard_port": 70000})

        self.assertEqual(config["proxy_port"], 8080)
        self.assertEqual(config["dashboard_port"], 8888)

    def test_validate_rejects_identical_ports(self):
        config, _errors = validate_config({"sites": {}, "proxy_port": 9000, "dashboard_port": 9000})

        self.assertNotEqual(config["proxy_port"], config["dashboard_port"])

    def test_validate_cleans_site_domain_lists(self):
        config, _errors = validate_config({"sites": {
            "a": {"domains": ["A.test", 3, "", "a.test"]},
            "b": {"domains": [None]},
        }})

        self.assertEqual(config["sites"]["a"]["domains"], ["a.test"])
        self.assertNotIn("b", config["sites"])


if __name__ == "__main__":
    unittest.main()
