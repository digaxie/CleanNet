import json
import os
import tempfile
import unittest

from cleannet.ai_engine import AdaptiveStrategyEngine, StrategyCache, parse_iso
from cleannet.strategy_catalog import STRATEGY_ORDER


class AiEngineTests(unittest.TestCase):
    def test_strategy_cache_forced_strategy_and_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = StrategyCache(
                os.path.join(tmp, "strategy_cache.json"),
                config_provider=lambda: {"sites": {"example": {"strategy": "host_split"}}},
                strategy_names={"direct", "host_split"},
                save_interval=0,
            )

            self.assertEqual(cache.get_strategy_order("example"), ["host_split"])

            cache.record_success("example", "direct", 100)
            cache.record_failure("example", "direct")
            cache.record_failure("example", "direct")
            cache.record_failure("example", "direct")

            self.assertEqual(cache.get_site_strategy_info("example")["strategy"], "auto")

    def test_adaptive_engine_records_and_predicts_after_min_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = AdaptiveStrategyEngine(
                os.path.join(tmp, "ai_strategy.json"),
                min_samples=2,
                save_interval=0,
            )

            engine.record("example", "host_split", True, 120)
            engine.record("example", "direct", False, 0)
            predictions = engine.predict("example", count_as_prediction=True)

            self.assertIsInstance(predictions, list)
            self.assertIn(predictions[0][0], STRATEGY_ORDER)
            self.assertGreaterEqual(engine.get_global_stats()["total_observations"], 2)

    def test_train_intensity_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            model_path = os.path.join(tmp, "ai_strategy.json")
            engine = AdaptiveStrategyEngine(model_path, save_interval=0)

            self.assertTrue(engine.set_train_intensity("heavy"))
            self.assertFalse(engine.set_train_intensity("invalid"))

            with open(model_path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["train_intensity"], "heavy")

    def test_parse_iso_handles_bad_values(self):
        self.assertIsNone(parse_iso(""))
        self.assertIsNone(parse_iso("not-a-date"))


if __name__ == "__main__":
    unittest.main()
