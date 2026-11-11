import os
import tempfile
import unittest

from packetlens.detectors import Alert
from packetlens.store import Store


class CaptureSummaryTests(unittest.TestCase):
    def test_capture_totals_and_quality_counters_are_additive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "capture.db")
            store = Store(path)
            try:
                store.record_capture("one.pcap", 12, 3400, 1, 100.0, 110.0, dropped_writes=2)
                store.record_capture("interface:eth0", 8, 1200, 0, 200.0, 205.0, dropped_writes=1)
                result = store.capture_summary()
                self.assertEqual(result["runs"], 2)
                self.assertEqual(result["packets"], 20)
                self.assertEqual(result["bytes"], 4600)
                self.assertEqual(result["malformed"], 1)
                self.assertEqual(result["dropped_writes"], 3)
                self.assertEqual((result["first_ts"], result["last_ts"]), (100.0, 205.0))
            finally:
                store.close()

    def test_negative_capture_counts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "capture.db"))
            try:
                with self.assertRaises(ValueError):
                    store.record_capture("bad", 1, -1, 0)
            finally:
                store.close()

    def test_open_incident_grouping_survives_store_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "capture.db")
            first_store = Store(path)
            first_id = first_store.add_alert(
                Alert(100.0, "port_scan", "high", "10.0.0.1", "first", "10.0.0.2"))
            first_store.close()

            second_store = Store(path)
            try:
                second_id = second_store.add_alert(
                    Alert(101.0, "port_scan", "critical", "10.0.0.1", "second", "10.0.0.2"))
                incident = second_store.get_incident(first_id)
                self.assertEqual(second_id, first_id)
                self.assertEqual(incident["count"], 2)
                self.assertEqual(incident["severity"], "critical")
                self.assertEqual(len(incident["alerts"]), 2)
            finally:
                second_store.close()


if __name__ == "__main__":
    unittest.main()
