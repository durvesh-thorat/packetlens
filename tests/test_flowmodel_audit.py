import contextlib
import io
import unittest

try:
    import pandas as pd
    from packetlens.flowmodel import _audit_label_windows
except (ImportError, RuntimeError):
    pd = None


@unittest.skipIf(pd is None, "pandas and scikit-learn are required")
class FlowModelAuditTests(unittest.TestCase):
    def test_audit_splits_window_counts_and_derives_attacker_ip(self):
        rows = [
            ("205.174.165.73", "192.168.10.5", 80, "2017-07-07 10:02", 1),
            ("205.174.165.73", "192.168.10.5", 80, "2017-07-07 11:03", 1),
            ("192.168.10.5", "205.174.165.73", 80, "2017-07-07 11:05", 0),
        ]
        frame = pd.DataFrame(
            rows, columns=["Source IP", "Destination IP", "Destination Port", "ts", "target"]
        )
        frame["ts"] = pd.to_datetime(frame["ts"])
        test = frame.iloc[:2].copy()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            audit = _audit_label_windows(frame, test, [1, 0], {"precision": 0.5})

        self.assertEqual(audit["attacker_ips"], ["205.174.165.73"])
        self.assertEqual(audit["h1_bot_flows_per_30min"], [
            {"slot": "2017-07-07 10:00", "inside": 1, "outside": 0},
            {"slot": "2017-07-07 11:00", "inside": 0, "outside": 1},
        ])
        self.assertEqual(audit["h2_attacker_flows_after_window"]["205.174.165.73"]
                         ["BENIGN_after_window"], 1)
        self.assertEqual(audit["h3_destination_pairs"]["fraction_also_inside"], 1.0)
        self.assertEqual(audit["h4_test_bot"], {
            "model": "Random forest",
            "threshold": 0.5,
            "precision": 0.5,
            "inside": {"tp": 1, "fn": 0},
            "outside": {"tp": 0, "fn": 1},
        })


if __name__ == "__main__":
    unittest.main()
