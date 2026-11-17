import json
import os
import random
import tempfile
import unittest

from cleannet.ai_engine import AdaptiveStrategyEngine, StrategyCache, parse_iso
from cleannet.strategy_catalog import AUTO_STRATEGY_ORDER, RETIRED_STRATEGIES, STRATEGY_ORDER


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


class RetiredStrategyTests(unittest.TestCase):
    def test_cache_never_auto_selects_retired_best_strategy(self):
        # A cache written before the retirement may hold sni_padding as "best"
        # (it was falsely scored as working); it must not be tried automatically.
        with tempfile.TemporaryDirectory() as tmp:
            cache = StrategyCache(
                os.path.join(tmp, "strategy_cache.json"),
                config_provider=lambda: {"sites": {"example": {}}},
                strategy_names=STRATEGY_ORDER,
                save_interval=0,
            )
            cache.record_success("example", "sni_padding", 10)

            order = cache.get_strategy_order("example", is_main=True)

            self.assertEqual(set(order) & RETIRED_STRATEGIES, set())
            self.assertEqual(order[0], AUTO_STRATEGY_ORDER[0])

    def test_locked_retired_strategy_is_still_honored(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = StrategyCache(
                os.path.join(tmp, "strategy_cache.json"),
                config_provider=lambda: {"sites": {"example": {"strategy": "dot_shuffle"}}},
                strategy_names=STRATEGY_ORDER,
                save_interval=0,
            )

            self.assertEqual(cache.get_strategy_order("example"), ["dot_shuffle"])

    def test_ai_predictions_exclude_retired(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = AdaptiveStrategyEngine(os.path.join(tmp, "ai.json"), min_samples=1, save_interval=0)
            for _ in range(5):
                engine.record("example", "sni_padding", True, 5)

            predicted = [row[0] for row in engine.predict("example")]

            self.assertEqual(set(predicted) & RETIRED_STRATEGIES, set())
            self.assertEqual(set(predicted), set(AUTO_STRATEGY_ORDER))



def _engine(tmp, **kwargs):
    kwargs.setdefault("save_interval", 3600)
    kwargs.setdefault("min_samples", 1)
    return AdaptiveStrategyEngine(os.path.join(tmp, "ai.json"), **kwargs)


class BanditEngineTests(unittest.TestCase):
    def test_rank_orders_known_good_untried_then_known_bad(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            for _ in range(5):
                engine.record("site", "tls_record_frag", True, 50)
                engine.record("site", "direct", False, 0)

            order = engine.rank("site")

            self.assertEqual(order[0], "tls_record_frag")
            self.assertEqual(order[-1], "direct")
            self.assertEqual(set(order), set(AUTO_STRATEGY_ORDER))

    def test_rank_is_deterministic_for_live_traffic(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            engine.record("site", "host_split", True, 80)
            engine.record("site", "desync", False, 0)

            self.assertEqual(len({tuple(engine.rank("site")) for _ in range(20)}), 1)

    def test_explore_mode_samples_while_rank_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, rng=random.Random(7))
            engine.record("site", "host_split", True, 80)

            tops = {engine.predict("site", explore=True)[0][0] for _ in range(30)}

            self.assertGreater(len(tops), 1)
            self.assertEqual(engine.rank("site")[0], "host_split")

    def test_discounting_follows_a_network_change(self):
        # The ISP starts blocking a strategy that used to work; the engine must switch
        # within a bounded number of observations instead of trusting old history.
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, discount=0.98)
            for _ in range(60):
                engine.record("site", "host_split", True, 40)
                engine.record("site", "tls_record_frag", True, 400)
            self.assertEqual(engine.rank("site")[0], "host_split")

            for step in range(1, 40):
                engine.record("site", "host_split", False, 0)
                engine.record("site", "tls_record_frag", True, 400)
                if engine.rank("site")[0] == "tls_record_frag":
                    break

            self.assertEqual(engine.rank("site")[0], "tls_record_frag")
            self.assertLessEqual(step, 3)

    def test_latency_only_breaks_ties(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            for _ in range(10):
                engine.record("site", "host_split", True, 1500)
                engine.record("site", "desync", True, 40)
            self.assertEqual(engine.rank("site")[0], "desync")

            for _ in range(4):
                engine.record("site", "desync", False, 0)
            self.assertEqual(engine.rank("site")[0], "host_split")

    def test_retired_strategies_are_never_ranked(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            for _ in range(10):
                engine.record("site", "dot_shuffle", True, 5)

            self.assertNotIn("dot_shuffle", engine.rank("site"))

    def test_predict_waits_for_min_samples_but_rank_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, min_samples=5)
            engine.record("site", "host_split", True, 30)

            self.assertIsNone(engine.predict("site"))
            self.assertIsNone(engine.get_site_insights("site"))
            self.assertEqual(engine.rank("site")[0], "host_split")
            self.assertEqual(engine.rank("unknown"), list(AUTO_STRATEGY_ORDER))

    def test_cross_site_prior_is_weak(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            for _ in range(50):
                engine.record("a", "desync", True, 30)
            engine._compute_global_reputation()

            # A new site starts with desync slightly favoured...
            self.assertEqual(engine.rank("b")[0], "desync")
            # ...but a few local failures outweigh the borrowed prior (it is worth two
            # observations; the cache additionally benches it after two in a row).
            for _ in range(3):
                engine.record("b", "desync", False, 0)
            self.assertNotEqual(engine.rank("b")[0], "desync")

    def test_connection_metrics_are_first_try_rate_and_connect_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            engine.record("site", "host_split", True, 30)
            engine.record_connection("site", True, 100.0)
            engine.record_connection("site", True, 100.0)
            engine.record_connection("site", False, 300.0)
            engine.record_connection("site", False, None)

            stats = engine.get_global_stats()
            insights = engine.get_site_insights("site")

            self.assertEqual(stats["accuracy"], 50.0)
            self.assertEqual(stats["first_try_rate"], 50.0)
            self.assertEqual(stats["total_predictions"], 4)
            self.assertIsNotNone(stats["avg_connect_ms"])
            self.assertAlmostEqual(insights["first_try_rate"], 50.0, delta=1.0)
            self.assertEqual(stats["engine_version"], 4)

    def test_saved_model_has_no_neural_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            engine.record("site", "host_split", True, 30)
            engine.force_save()

            with open(os.path.join(tmp, "ai.json"), encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(data["version"], 4)
            self.assertNotIn("nn_weights", json.dumps(data))

    def test_migrates_v3_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            v3 = {
                "version": 3,
                "train_intensity": "medium",
                "sites": {"discord": {
                    "thompson": {"tls_record_frag": {"alpha": 200.0, "beta": 2.0}, "direct": {"alpha": 1.0, "beta": 9.0}},
                    "strategy_scores": {"tls_record_frag": {"ema_success": 0.9, "ema_latency": 80.0}},
                    "recent": [["tls_record_frag", True, 80.0, 10, 2, 1.0]],
                    "hour_matrix": {"10": {"tls_record_frag": {"ok": 3, "fail": 0}}},
                    "total_observations": 210,
                    "nn_weights": {"W1": []},
                }},
            }
            with open(os.path.join(tmp, "ai.json"), "w", encoding="utf-8") as f:
                json.dump(v3, f)

            engine = _engine(tmp)
            arm = engine._data["sites"]["discord"]["arms"]["tls_record_frag"]

            self.assertEqual(engine.train_intensity, "medium")
            self.assertEqual(engine.rank("discord")[0], "tls_record_frag")
            self.assertEqual(engine.rank("discord")[-1], "direct")
            # Old evidence is capped so the new discounting can still move it.
            self.assertLessEqual(arm["a"] + arm["b"] - 2.0, 20.01)
            self.assertEqual(arm["latency_ms"], 80.0)
            self.assertNotIn("nn_weights", engine._data["sites"]["discord"])


class StrategyCacheOrderingTests(unittest.TestCase):
    def _cache(self, tmp, engine, config=None):
        return StrategyCache(
            os.path.join(tmp, "cache.json"),
            config_provider=lambda: config or {"sites": {"site": {}}},
            strategy_names=STRATEGY_ORDER,
            ai_engine_provider=lambda: engine,
            save_interval=3600,
        )

    def test_order_comes_from_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            for _ in range(3):
                engine.record("site", "tls_record_frag", True, 40)

            self.assertEqual(self._cache(tmp, engine).get_strategy_order("site")[0], "tls_record_frag")

    def test_single_failure_does_not_bench_a_strategy(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            cache = self._cache(tmp, engine)
            for _ in range(20):
                engine.record("site", "tls_record_frag", True, 40)
                cache.record_success("site", "tls_record_frag", 40)
            engine.record("site", "tls_record_frag", False, 0)
            cache.record_failure("site", "tls_record_frag")

            self.assertEqual(cache.get_strategy_order("site")[0], "tls_record_frag")

            engine.record("site", "tls_record_frag", False, 0)
            cache.record_failure("site", "tls_record_frag")
            self.assertNotIn("tls_record_frag", cache.get_strategy_order("site"))
            # CDN/non-main lookups ignore the cooldown.
            self.assertIn("tls_record_frag", cache.get_strategy_order("site", is_main=False))

    def test_site_info_reports_engine_top(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            cache = self._cache(tmp, engine)
            for _ in range(3):
                engine.record("site", "sni_multi_record", True, 25)
                cache.record_success("site", "sni_multi_record", 25)

            self.assertEqual(cache.get_site_strategy_info("site"), {"strategy": "sni_multi_record", "time_ms": 25.0})


if __name__ == "__main__":
    unittest.main()
