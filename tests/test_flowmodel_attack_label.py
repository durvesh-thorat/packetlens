import csv
import tempfile
import unittest
from pathlib import Path

try:
    from research.flowmodel import load_flow_data
except RuntimeError:
    load_flow_data = None


@unittest.skipIf(load_flow_data is None, "pandas and scikit-learn are required")
class AttackLabelTests(unittest.TestCase):
    def test_load_flow_data_retains_the_requested_attack_and_benign(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows.csv"
            with path.open("w", encoding="latin-1", newline="") as output:
                writer = csv.writer(output)
                writer.writerow(("Timestamp", "Label", "Metric"))
                writer.writerows((
                    ("7/7/2017 9:00", "BENIGN", "1"),
                    ("7/7/2017 9:01", "PortScan", "2"),
                    ("7/7/2017 9:02", "Bot", "3"),
                    ("7/7/2017 9:03", "DDoS", "4"),
                ))

            frame, dropped = load_flow_data(path, attack_label="PortScan")

        self.assertEqual(dropped, 2)
        self.assertEqual(frame["label"].tolist(), ["BENIGN", "PortScan"])
        self.assertEqual(frame["target"].tolist(), [0, 1])

    def test_benign_cannot_be_used_as_the_attack_label(self):
        with self.assertRaises(ValueError):
            load_flow_data("unused.csv", attack_label="BENIGN")


if __name__ == "__main__":
    unittest.main()
