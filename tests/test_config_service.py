import unittest

from cleannet.config_service import ConfigMutationContext, ConfigMutationService


class _Logger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(message)


class ConfigMutationServiceTests(unittest.TestCase):
    def _service(self):
        state = {"saves": 0, "reloads": 0}
        logger = _Logger()
        config = {
            "sites": {
                "example": {
                    "enabled": True,
                    "domains": ["example.com"],
                    "dns_resolve": ["example.com"],
                    "ips": [],
                }
            },
            "proxy_bypass": [],
            "privacy": {"hide_dns": False, "hide_sni": False},
            "performance": {
                "low_latency_mode": True,
                "background_training": False,
                "health_check_interval": 120,
                "ip_update_interval": 1800,
                "ping_target_host": "1.1.1.1",
            },
        }
        service = ConfigMutationService(
            ConfigMutationContext(
                logger=logger,
                get_config=lambda: config,
                save_config=lambda: state.__setitem__("saves", state["saves"] + 1),
                reload_config=lambda: state.__setitem__("reloads", state["reloads"] + 1) or True,
                always_bypass=["localhost"],
                bypass_presets={"gaming": ["*.riotgames.com", "*.steamcommunity.com"]},
            )
        )
        return service, config, state, logger

    def test_toggle_site_saves_reloads_and_requests_ip_refresh(self):
        service, config, state, _logger = self._service()

        result = service.toggle_site("example")

        self.assertFalse(config["sites"]["example"]["enabled"])
        self.assertEqual(state, {"saves": 1, "reloads": 1})
        self.assertTrue(result.changed)
        self.assertTrue(result.refresh_ips)

    def test_add_site_uses_domain_defaults(self):
        service, config, state, _logger = self._service()

        result = service.add_site({"domain": "www.NewSite.com"})

        self.assertIn("newsite", config["sites"])
        self.assertEqual(config["sites"]["newsite"]["domains"], ["www.newsite.com", "www.www.newsite.com"])
        self.assertEqual(state, {"saves": 1, "reloads": 1})
        self.assertTrue(result.refresh_ips)

    def test_add_and_remove_cdn_domain_update_domain_lists(self):
        service, config, state, _logger = self._service()

        add_result = service.add_cdn_domain("example", "cdn.example.com")
        remove_result = service.remove_domain("example", "cdn.example.com")

        self.assertNotIn("cdn.example.com", config["sites"]["example"]["domains"])
        self.assertNotIn("cdn.example.com", config["sites"]["example"]["dns_resolve"])
        self.assertEqual(state, {"saves": 2, "reloads": 2})
        self.assertTrue(add_result.refresh_ips)
        self.assertTrue(remove_result.refresh_ips)

    def test_bypass_preserves_always_bypass_and_loads_presets(self):
        service, config, state, _logger = self._service()

        blocked = service.add_bypass("localhost")
        added = service.add_bypass("*.example.com")
        preset = service.load_preset("gaming")

        self.assertFalse(blocked.changed)
        self.assertTrue(added.changed)
        self.assertTrue(preset.changed)
        self.assertEqual(config["proxy_bypass"], ["*.example.com", "*.riotgames.com", "*.steamcommunity.com"])
        self.assertEqual(state, {"saves": 2, "reloads": 2})

    def test_batch_bypass_skips_duplicates(self):
        service, config, state, _logger = self._service()

        result = service.add_bypass_entries(["203.0.113.10", "203.0.113.10", "localhost", ""])

        self.assertTrue(result.changed)
        self.assertEqual(config["proxy_bypass"], ["203.0.113.10"])
        self.assertEqual(state, {"saves": 1, "reloads": 1})

    def test_set_performance_updates_valid_values(self):
        service, config, state, _logger = self._service()

        result = service.set_performance({
            "low_latency_mode": False,
            "background_training": True,
            "health_check_interval": 300,
            "ip_update_interval": 900,
            "ping_target_host": "8.8.8.8",
        })

        self.assertTrue(result.changed)
        self.assertFalse(config["performance"]["low_latency_mode"])
        self.assertTrue(config["performance"]["background_training"])
        self.assertEqual(config["performance"]["health_check_interval"], 300)
        self.assertEqual(config["performance"]["ip_update_interval"], 900)
        self.assertEqual(config["performance"]["ping_target_host"], "8.8.8.8")
        self.assertEqual(state, {"saves": 1, "reloads": 1})

    def test_set_site_strategy_lock_and_auto(self):
        service, config, state, _logger = self._service()

        locked = service.set_site_strategy("example", "host_split", {"direct", "host_split"})
        invalid = service.set_site_strategy("example", "bad", {"direct", "host_split"})
        auto = service.set_site_strategy("example", "auto", {"direct", "host_split"})

        self.assertTrue(locked.changed)
        self.assertFalse(invalid.changed)
        self.assertTrue(auto.changed)
        self.assertNotIn("strategy", config["sites"]["example"])
        self.assertEqual(state, {"saves": 2, "reloads": 2})

    def test_preset_load_skips_built_in_and_duplicate_entries(self):
        service, config, state, _logger = self._service()
        service.ctx.bypass_presets = {"cdn": ["localhost", "*.example.com"]}

        first = service.load_preset("cdn")
        second = service.load_preset("cdn")

        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        self.assertEqual(config["proxy_bypass"], ["*.example.com"])
        self.assertEqual(state, {"saves": 1, "reloads": 1})

    def test_privacy_setting_saves_without_reload(self):
        service, config, state, _logger = self._service()

        self.assertTrue(service.set_privacy("hide_dns", True))
        self.assertFalse(service.set_privacy("bad", True))

        self.assertTrue(config["privacy"]["hide_dns"])
        self.assertEqual(state, {"saves": 1, "reloads": 0})

    def test_import_config_requires_sites(self):
        service, config, state, _logger = self._service()

        invalid = service.import_config({"privacy": {"hide_dns": True}})
        valid = service.import_config({"sites": {"new": {"domains": ["new.test"]}}, "proxy_bypass": ["*.new.test"]})

        self.assertFalse(invalid.changed)
        self.assertTrue(valid.changed)
        self.assertIn("new", config["sites"])
        self.assertEqual(config["proxy_bypass"], ["*.new.test"])
        self.assertEqual(state, {"saves": 1, "reloads": 1})


if __name__ == "__main__":
    unittest.main()
