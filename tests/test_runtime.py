import unittest

from cleannet.config import build_lists_from_config
from cleannet.runtime import ConnectionTracker, RuntimeState


class RuntimeTests(unittest.TestCase):
    def test_connection_tracker_tracks_and_releases(self):
        tracker = ConnectionTracker()

        cid = tracker.track("example.com", 443, "example", "bypass")
        rows = tracker.snapshot()

        self.assertEqual(tracker.count(), 1)
        self.assertEqual(rows[0]["id"], cid)
        self.assertEqual(rows[0]["host"], "example.com")
        self.assertEqual(rows[0]["site"], "example")
        self.assertIn("age_s", rows[0])

        tracker.release(cid)

        self.assertEqual(tracker.count(), 0)
        self.assertEqual(tracker.snapshot(), [])

    def test_runtime_state_builds_config_derived_lists_and_lookups(self):
        config = {
            "sites": {
                "discord": {
                    "enabled": True,
                    "domains": ["discord.com"],
                    "dns_resolve": ["discord.com"],
                    "ips": ["1.1.1.1"],
                }
            },
            "privacy": {"hide_dns": True, "hide_sni": False},
        }
        state = RuntimeState.from_config(config, build_lists_from_config)

        self.assertEqual(state.find_site_for_host("cdn.discord.com"), "discord")
        self.assertEqual(state.get_site_ips("discord.com"), ["1.1.1.1"])
        self.assertEqual(state.get_privacy_settings(), {"hide_dns": True, "hide_sni": False})

        state.domain_ips["discord.com"] = ["2.2.2.2"]
        self.assertEqual(state.get_domain_ips("discord.com"), ["2.2.2.2"])
        self.assertEqual(state.get_bypass_ip("discord.com"), "2.2.2.2")

    def test_runtime_state_apply_config_refreshes_site_maps_and_dns_cache(self):
        state = RuntimeState.from_config({
            "sites": {
                "old": {
                    "enabled": True,
                    "domains": ["old.example"],
                    "dns_resolve": ["old.example"],
                    "ips": ["1.1.1.1"],
                }
            }
        }, build_lists_from_config)
        state.domain_ips["old.example"] = ["9.9.9.9"]
        state.dns_privacy_cache["old.example"] = {"ips": ["9.9.9.9"], "ts": 1}

        state.apply_config({
            "sites": {
                "new": {
                    "enabled": True,
                    "domains": ["new.example"],
                    "dns_resolve": ["new.example"],
                    "ips": ["2.2.2.2"],
                }
            }
        }, build_lists_from_config)

        self.assertEqual(state.site_names, ["new"])
        self.assertIsNone(state.find_site_for_host("old.example"))
        self.assertEqual(state.find_site_for_host("new.example"), "new")
        self.assertEqual(state.domain_ips, {})
        self.assertEqual(state.dns_privacy_cache, {})


if __name__ == "__main__":
    unittest.main()
