import unittest

from cleannet.config import DEFAULT_CONFIG, build_lists_from_config, default_config, validate_config
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
        self.assertTrue(config["privacy"]["hide_dns"])
        self.assertTrue(config["privacy"]["hide_sni"])
        self.assertTrue(config["performance"]["low_latency_mode"])
        self.assertFalse(config["performance"]["background_training"])
        self.assertEqual(config["performance"]["ip_update_interval"], 1800)
        self.assertGreaterEqual(len(errors), 4)

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


if __name__ == "__main__":
    unittest.main()
