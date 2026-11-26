import importlib.util
import random
import tempfile
import unittest
from pathlib import Path

try:
    import pandas as pd
    from research.flows import evaluate_flows, load_flows, to_series
except (ImportError, RuntimeError):      # pandas not installed: skip
    pd = None

SKLEARN_AVAILABLE = importlib.util.find_spec("sklearn") is not None

COLS = [" Source IP", " Destination IP", " Destination Port", " Timestamp", " Total Fwd Packets",
        " Total Backward Packets", "Total Length of Fwd Packets", " Total Length of Bwd Packets",
        " SYN Flag Count", " Label"]


def write_csv(path, rows, extra_header_row=False):
    lines = [",".join(COLS)]
    for i, r in enumerate(rows):
        lines.append(",".join(str(x) for x in r))
        if extra_header_row and i == 3:
            lines.append(",".join(COLS))              # header repeated mid-file, as in the real data
    Path(path).write_bytes("\n".join(lines).encode("latin-1"))


def day_rows(rng, start_hour12, minutes, attack=None, base=40):
    """Rows in CIC style: d/m/yyyy h:mm, 12-hour clock without am/pm."""
    rows = []
    for m in range(minutes):
        h, mm = start_hour12 + m // 60, m % 60
        n = base + rng.randint(-8, 8)
        for _ in range(n):
            rows.append([f"192.168.10.{rng.randint(5, 30)}", "192.168.10.50", rng.choice((80, 443, 22)),
                         f"7/7/2017 {h}:{mm:02d}", rng.randint(1, 20), rng.randint(1, 20),
                         rng.randint(100, 5000), rng.randint(100, 9000), rng.randint(0, 1), "BENIGN"])
        if attack and attack[0] <= m < attack[1]:
            for _ in range(400):
                rows.append(["205.174.165.69", "192.168.10.50", 80, f"7/7/2017 {h}:{mm:02d}",
                             3, 0, 300, 0, 1, "DDoS"])
    return rows


@unittest.skipIf(pd is None, "pandas not installed")
class FlowTests(unittest.TestCase):
    def test_cleaning_and_pm_fix(self):
        d = tempfile.mkdtemp()
        rows = day_rows(random.Random(1), 3, 5)               # "3:xx" means 15:xx
        rows.append(["1.1.1.1", "2.2.2.2", 80, "7/7/2017 3:02", "Infinity", "", 5, 5, 0, "Web Attack \x96 XSS"])
        write_csv(f"{d}/a.csv", rows, extra_header_row=True)
        df = load_flows(f"{d}/a.csv")
        self.assertEqual(len(df), len(rows))                  # repeated header row dropped
        self.assertEqual(int(df["ts"].dt.hour.min()), 15)
        self.assertIn("Web Attack - XSS", set(df["label"]))
        self.assertEqual(float(df["Total Fwd Packets"].iloc[-1]), 0)   # 'Infinity' became 0

    def test_series_labels(self):
        d = tempfile.mkdtemp()
        write_csv(f"{d}/a.csv", day_rows(random.Random(2), 3, 30, attack=(10, 15)))
        s, lb = to_series(load_flows(f"{d}/a.csv"))
        self.assertEqual(int(s["attack"].sum()), 5)
        self.assertEqual(len(lb["DDoS"]), 5)

    def test_bad_date_order_is_rejected(self):
        d = tempfile.mkdtemp()
        write_csv(f"{d}/a.csv", [["1.1.1.1", "2.2.2.2", 80, "13/1/2017 9:00", 1, 1, 1, 1, 0, "BENIGN"]] * 5)
        with self.assertRaises(ValueError):
            load_flows(f"{d}/a.csv")

    def test_end_to_end_detects_synthetic_ddos(self):
        d = tempfile.mkdtemp()
        write_csv(f"{d}/mon.csv", day_rows(random.Random(3), 9, 300))
        write_csv(f"{d}/fri.csv", day_rows(random.Random(4), 3, 60, attack=(30, 40)))
        r = evaluate_flows(f"{d}/mon.csv", f"{d}/fri.csv")
        expected_methods = {"zscore_adaptive", "zscore_frozen"}
        if SKLEARN_AVAILABLE:
            expected_methods.add("isolation_forest")
        self.assertEqual(set(r["methods"]), expected_methods)
        self.assertGreaterEqual(r["methods"]["zscore_adaptive"]["recall"], 0.8)
        self.assertEqual(r["methods"]["zscore_adaptive"]["recall_by_attack"]["DDoS"] >= 0.8, True)

    @unittest.skipUnless(SKLEARN_AVAILABLE, "scikit-learn not installed")
    def test_end_to_end_includes_isolation_forest(self):
        d = tempfile.mkdtemp()
        write_csv(f"{d}/mon.csv", day_rows(random.Random(3), 9, 300))
        write_csv(f"{d}/fri.csv", day_rows(random.Random(4), 3, 60, attack=(30, 40)))
        r = evaluate_flows(f"{d}/mon.csv", f"{d}/fri.csv")
        self.assertIn("isolation_forest", r["methods"])


if __name__ == "__main__":
    unittest.main()
