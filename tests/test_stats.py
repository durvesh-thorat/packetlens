import unittest

from packetlens.stats import block_bootstrap


class BlockBootstrapTests(unittest.TestCase):
    def test_empty_and_tiny_samples_have_no_interval_and_explain_why(self):
        self.assertEqual(block_bootstrap([], []), (None, "empty sample"))
        estimate, note = block_bootstrap([True] * 29, [True] * 29)
        self.assertIsNone(estimate)
        self.assertEqual(note, "too few to trust")

    def test_known_metrics_and_seeded_intervals(self):
        truth = [True] * 15 + [False] * 15
        prediction = [True] * 10 + [False] * 5 + [True] * 5 + [False] * 10

        estimate, note = block_bootstrap(
            truth, prediction, block_length=5, bin_seconds=60, resamples=1000, seed=7)
        repeated, repeated_note = block_bootstrap(
            truth, prediction, block_length=5, bin_seconds=60, resamples=1000, seed=7)

        self.assertIsNone(note)
        self.assertIsNone(repeated_note)
        self.assertEqual(estimate, repeated)
        self.assertEqual(estimate["n"], 30)
        self.assertAlmostEqual(estimate["point"]["precision"], 2 / 3)
        self.assertAlmostEqual(estimate["point"]["recall"], 2 / 3)
        self.assertAlmostEqual(estimate["point"]["f1"], 2 / 3)
        self.assertAlmostEqual(estimate["point"]["false_alarms_per_hour"], 10)
        for bounds in estimate["ci95"].values():
            self.assertEqual(len(bounds), 2)
            self.assertLessEqual(bounds[0], bounds[1])

    def test_rows_within_each_time_bin_are_counted_together(self):
        truth = [[True, False]] * 30
        prediction = [[True, True]] * 30

        estimate, note = block_bootstrap(truth, prediction, resamples=5)

        self.assertIsNone(note)
        self.assertEqual(estimate["point"]["precision"], 0.5)
        self.assertEqual(estimate["point"]["recall"], 1.0)
        self.assertEqual(estimate["point"]["false_alarms_per_hour"], 60.0)


if __name__ == "__main__":
    unittest.main()
