import copy
import math
import unittest

try:
    import torch
    from tsfm_public.toolkit.get_model import get_model
except ImportError:
    GRANITE_AVAILABLE = False
else:
    GRANITE_AVAILABLE = True

from packetlens.ml import GraniteForecastDetector


@unittest.skipUnless(GRANITE_AVAILABLE, "torch and tsfm_public are required")
class GraniteForecastTests(unittest.TestCase):
    @staticmethod
    def fake_forecaster(context):
        return context[-1]

    @staticmethod
    def bins(count):
        return [{"flows": float((index * 7) % 23)} for index in range(count)]

    def test_future_bin_changes_do_not_change_earlier_scores(self):
        detector = GraniteForecastDetector(forecaster=self.fake_forecaster)
        original = self.bins(130)
        changed = copy.deepcopy(original)
        changed_at = 105
        changed[changed_at]["flows"] += 10000

        original_scores = detector._rolling_residuals(original)
        changed_scores = detector._rolling_residuals(changed)

        self.assertEqual(original_scores[:changed_at], changed_scores[:changed_at])

    def test_threshold_uses_training_residuals_only(self):
        detector = GraniteForecastDetector(forecaster=self.fake_forecaster)
        training = self.bins(140)
        detector.fit(training)

        training_residuals = [value for value in detector._rolling_residuals(training) if value is not None]
        mean = sum(training_residuals) / len(training_residuals)
        spread = math.sqrt(sum((value - mean) ** 2 for value in training_residuals) / len(training_residuals))
        expected_spread = spread if spread > 0 else max(abs(mean), 1.0)
        scores = sorted(value / expected_spread for value in training_residuals)
        allowed = min(math.floor(len(training_residuals) / 60), len(scores))
        expected_threshold = (scores[0] - 1e-12 if allowed == len(scores)
                              else scores[len(scores) - allowed - 1])
        threshold = detector.threshold

        detector.predict([{"flows": 1000000.0 + index} for index in range(130)])

        self.assertAlmostEqual(detector.residual_spread, expected_spread)
        self.assertAlmostEqual(threshold, expected_threshold)
        self.assertEqual(detector.threshold, threshold)
        self.assertEqual(detector.calibration_bins, len(training))

    def test_fit_and_predict_return_boolean_lists_of_the_right_length(self):
        detector = GraniteForecastDetector(forecaster=self.fake_forecaster)
        self.assertIs(detector.fit(self.bins(140)), detector)

        prediction = detector.predict(self.bins(97))

        self.assertIsInstance(prediction, list)
        self.assertEqual(len(prediction), 97)
        self.assertTrue(all(type(value) is bool for value in prediction))


if __name__ == "__main__":
    unittest.main()
