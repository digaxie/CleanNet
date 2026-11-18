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


class RecommendationCodeTests(unittest.TestCase):
    def test_every_recommendation_has_a_stable_code(self):
        # The dashboard localizes recommendations by code, not by English title.
        recs = build_strategy_recommendations(
            {"a": {"enabled": False}, "b": {"enabled": True}},
            {"b": {"connections": 10, "successes": 1, "failures": 9}},
            {"total_observations": 50, "accuracy": 20},
            [{"success": False}] * 20,
            [{}] * 25,
            verification={"b": {"intercepted_recently": True, "last": {"status": "intercepted"}}},
        )

        codes = [r.get("code") for r in recs]
        self.assertTrue(all(codes), recs)
        self.assertEqual(codes[0], "dpi_intercepted")
        self.assertIn("site_disabled", codes)
        self.assertIn("high_failure_rate", codes)

    def test_low_first_try_replaces_old_accuracy_wording(self):
        recs = build_strategy_recommendations({}, {}, {"total_observations": 50, "accuracy": 10}, [], [])

        self.assertEqual([r["code"] for r in recs], ["low_first_try"])
        self.assertNotIn("prediction", recs[0]["title"].lower())

if __name__ == "__main__":
    unittest.main()

