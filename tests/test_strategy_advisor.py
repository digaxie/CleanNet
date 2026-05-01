import unittest

from cleannet.strategy_advisor import build_strategy_recommendations


class StrategyAdvisorTests(unittest.TestCase):
    def test_recommends_for_empty_ip_pool_and_warmup(self):
        recs = build_strategy_recommendations(
            {"example": {"enabled": True, "domains": ["example.com"], "ips": []}},
            {"example": {"connections": 0, "successes": 0, "failures": 0}},
            {"total_observations": 0, "accuracy": 0},
            [],
            [],
        )

        titles = {item["title"] for item in recs}
        self.assertIn("No pinned IP pool", titles)
        self.assertIn("No traffic observed", titles)
        self.assertIn("AI still warming up", titles)

    def test_recommends_training_on_high_failure_rate(self):
        recs = build_strategy_recommendations(
            {"example": {"enabled": True, "domains": ["example.com"], "ips": ["203.0.113.5"]}},
            {"example": {"connections": 8, "successes": 2, "failures": 6}},
            {"total_observations": 30, "accuracy": 80},
            [],
            [],
        )

        self.assertTrue(any(item["level"] == "critical" for item in recs))


if __name__ == "__main__":
    unittest.main()

