import copy
import unittest

from packetlens.timeseries import EwmaZScoreDetector


class EwmaFreezeTests(unittest.TestCase):
    def test_freeze_preserves_state_and_flags_spikes(self):
        detector = EwmaZScoreDetector(metrics=("packets",), warmup=30)
        for t in range(60):
            detector.update({"t": t, "packets": 100})
        detector.freeze()
        state = copy.deepcopy(detector._s)

        for t in range(60, 160):
            detector.update({"t": t, "packets": 1000})
            self.assertIn("packets", detector.last_flags)

        self.assertEqual(detector._s, state)


if __name__ == "__main__":
    unittest.main()
