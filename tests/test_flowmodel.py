import contextlib
import csv
import inspect
import io
import json
import tempfile
import unittest
from pathlib import Path

try:
    import pandas as pd
    from packetlens.flowmodel import (feature_columns, load_flow_data, select_alarm_threshold,
                                      split_cleaner_machine_rows, split_held_out_machines, time_split)
    from packetlens.cli import main
except (ImportError, RuntimeError):
    pd = None


@unittest.skipIf(pd is None, "pandas and scikit-learn are required")
class FlowModelTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "flows.csv"
        self.columns = [
            "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
            "Timestamp", "Label",
        ] + [f"Metric {index}" for index in range(12)]
        rows = []
        for index in range(80):
            label = "Bot" if index % 2 else "BENIGN"
            timestamp = f"7/7/2017 {8 + index // 60}:{index % 60:02d}"
            row = [f"flow-{index}", f"192.168.10.{index % 4 + 1}", 1000 + index, "192.168.10.50",
                   80 + index % 4, timestamp, label]
            row.extend(index + feature for feature in range(12))
            rows.append(row)
        with self.path.open("w", encoding="latin-1", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(self.columns)
            writer.writerows(rows)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_identifiers_are_excluded_from_main_features(self):
        frame, dropped = load_flow_data(self.path)
        self.assertEqual(dropped, 0)
        features = feature_columns(frame)
        self.assertTrue(set(self.columns[:6]).isdisjoint(features))
        self.assertEqual(len([name for name in features if name.startswith("Metric ")]), 12)

    def test_split_is_chronological(self):
        frame, _ = load_flow_data(self.path)
        train, test = time_split(frame, 0.6)
        self.assertLessEqual(train["ts"].max(), test["ts"].min())

    def test_cli_runs_end_to_end(self):
        output = io.StringIO()
        result_path = Path(self.temp_dir.name) / "flowmodel.json"
        with contextlib.redirect_stdout(output):
            main(["flowmodel", "--file", str(self.path), "--save", str(result_path)])
        self.assertIn("| Random forest |", output.getvalue())
        self.assertIn("Top 10 RandomForest feature importances:", output.getvalue())
        self.assertIn("Exact-duplicate rates by test class", output.getvalue())
        report = json.loads(result_path.read_text(encoding="utf-8"))
        forest = next(row for row in report["results"] if row["model"] == "Random forest")
        self.assertGreaterEqual(forest["metrics"]["bootstrap"]["precision"]["n"], 30)
        self.assertEqual(set(report["duplicate_check"]["per_class"]), {"Bot", "BENIGN"})
        self.assertIn("precision", report["duplicate_check"]["duplicate_free_test"]["metrics"])
        self.assertIn("recall", report["duplicate_check"]["duplicate_free_test"]["metrics"])
        self.assertEqual(report["meta"]["dataset_files"][0]["name"], self.path.name)

    def test_alarm_threshold_uses_validation_inputs_only(self):
        labels = [0, 0, 0, 0, 1, 1]
        scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
        threshold, rate = select_alarm_threshold(labels, scores, 250)
        self.assertEqual(threshold, 0.4)
        self.assertEqual(rate, 250)
        self.assertEqual(
            set(inspect.signature(select_alarm_threshold).parameters),
            {"validation_labels", "validation_scores", "budget"},
        )

    def test_held_out_machine_split_shares_no_source_ip(self):
        frame, _ = load_flow_data(self.path)
        train, test, _, _ = split_held_out_machines(frame)
        self.assertTrue(set(train["Source IP"]).isdisjoint(set(test["Source IP"])))

    def test_cleaner_machine_split_excludes_held_out_ips_from_both_train_columns(self):
        frame, _ = load_flow_data(self.path)
        _, _, held_out_ips, _ = split_held_out_machines(frame)
        train, test = split_cleaner_machine_rows(frame, held_out_ips)
        held_out = set(held_out_ips)
        self.assertTrue(set(train["Source IP"]).isdisjoint(held_out))
        self.assertTrue(set(train["Destination IP"]).isdisjoint(held_out))
        self.assertTrue(set(test["Source IP"]).issubset(held_out))

    def test_extended_cli_runs_end_to_end(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["flowmodel", "--file", str(self.path), "--extended"])
        report = output.getvalue()
        for title in ("A. Alarm-budget thresholds", "B. Held-out machines",
                      "C. Duplicate-free test", "D. Feature ablation"):
            self.assertIn(title, report)

    def test_diagnose_cli_runs_end_to_end(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["flowmodel", "--file", str(self.path), "--diagnose"])
        report = output.getvalue()
        for title in ("E. Per-source breakdown", "F. Cleaner machine split",
                      "G. Cleaner machine split excluding external Bot sources"):
            self.assertIn(title, report)


if __name__ == "__main__":
    unittest.main()
