import unittest

from cleannet.strategy_catalog import (
    AI_TRAIN_PROFILES,
    STRATEGY_GROUPS,
    STRATEGY_ORDER,
    STRATEGY_TO_GROUP,
    normalize_train_intensity,
)


class StrategyCatalogTests(unittest.TestCase):
    def test_catalog_has_expected_core_strategies(self):
        self.assertIn("direct", STRATEGY_ORDER)
        self.assertIn("host_split", STRATEGY_ORDER)
        self.assertIn("tcp_window_frag", STRATEGY_ORDER)
        self.assertEqual(STRATEGY_TO_GROUP["direct"], "direct")

    def test_strategy_groups_cover_catalog(self):
        covered = {strategy for strategies in STRATEGY_GROUPS.values() for strategy in strategies}

        self.assertEqual([strategy for strategy in STRATEGY_ORDER if strategy not in covered], [])
        self.assertEqual([strategy for strategy in covered if strategy not in STRATEGY_ORDER], [])

    def test_normalize_training_intensity(self):
        self.assertEqual(normalize_train_intensity("heavy"), "heavy")
        self.assertEqual(normalize_train_intensity("bad", "medium"), "medium")
        self.assertEqual(normalize_train_intensity("bad", ""), "")
        self.assertIn("nonstop", AI_TRAIN_PROFILES)


if __name__ == "__main__":
    unittest.main()
