import http.client
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer

from packetlens import synth
from packetlens.dashboard import SOURCE_STALE_AFTER_S, SourceHealth, _consume, make_handler
from packetlens.detectors import Alert, HorizontalScanDetector, PortScanDetector
from packetlens.engine import Engine
from packetlens.hosts import HostTable
from packetlens.parsers import SYN
from packetlens.policy import effective_policy
from packetlens.store import Store


ROOT = Path(__file__).resolve().parents[1]


class ReliabilityAndObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp.name, "reliability.db")

    def tearDown(self):
        self.temp.cleanup()

    def _start_dashboard(self, engine, store):
        source_health = SourceHealth(engine, time.monotonic())
        handler = make_handler(
            engine, store, "rel-token", "reliability-test",
            effective_policy(), Path(self.temp.name) / "results",
            time.monotonic(), source_health=source_health,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, source_health

    @staticmethod
    def _get_health(port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            conn.request("GET", "/api/health")
            resp = conn.getresponse()
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, body
        finally:
            conn.close()

    def test_graceful_shutdown_flushes_all_records_without_loss(self):
        frames, _ = synth.generate(300, seed=8, attacks=True)
        store = Store(self.db_path)
        engine = Engine(store=store, policy=effective_policy())
        for ts, frame in frames:
            engine.process(ts, frame)
        engine.finish()
        snap = engine.snapshot()
        store.record_capture("graceful.pcap", snap["total_packets"], snap["total_bytes"],
                             snap["malformed"], frames[0][0], frames[-1][0],
                             store.counters()["dropped"])
        counters = store.counters()
        self.assertEqual(counters["dropped"], 0)
        self.assertEqual(counters["status"], "ok")
        self.assertGreater(snap["avg_processing_us"], 0.0)
        self.assertGreaterEqual(snap["max_processing_us"], snap["avg_processing_us"])
        store.close()

        reopened = Store(self.db_path)
        try:
            summary = reopened.capture_summary()
            self.assertEqual(summary["packets"], len(frames))
            self.assertEqual(summary["dropped_writes"], 0)
            self.assertGreater(reopened.summary()["total_alerts"], 0)
            self.assertGreater(reopened.list_hosts()["total"], 0)
            self.assertGreater(len(reopened.minute_stats(0, 1_900_000_000)), 0)
        finally:
            reopened.close()

    def test_queue_overload_sets_degraded_health(self):
        store = Store(self.db_path, queue_capacity=1)
        engine = Engine(store=store)
        server, thread, _source_health = self._start_dashboard(engine, store)
        try:
            entered, release = threading.Event(), threading.Event()
            store._enqueue(lambda _conn: (entered.set(), release.wait(5)))
            self.assertTrue(entered.wait(2))
            store._enqueue(lambda _conn: None)
            self.assertIsNone(store._enqueue(lambda _conn: None))
            release.set()
            store.flush()

            counters = store.counters()
            self.assertEqual(counters["dropped"], 1)
            self.assertEqual(counters["queue_capacity"], 1)
            self.assertEqual(counters["status"], "degraded")

            status, health = self._get_health(server.server_address[1])
            self.assertEqual(status, 200)
            self.assertEqual(health["service_status"], "degraded")
            self.assertEqual(health["store_status"], "degraded")
            self.assertIn("store_drops", health["degraded_reasons"])
            self.assertIsNotNone(health["memory_rss_bytes"])
            self.assertGreater(health["memory_rss_bytes"], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            store.close()

    def test_disk_full_writer_error_is_visible_in_store_and_health(self):
        store = Store(self.db_path)
        engine = Engine(store=store)
        server, thread, _source_health = self._start_dashboard(engine, store)
        try:
            def fail_disk_full(_connection):
                raise sqlite3.OperationalError("database or disk is full")

            store._enqueue(fail_disk_full)
            deadline = time.monotonic() + 2.0
            while store.counters()["writer_error"] is None and time.monotonic() < deadline:
                time.sleep(0.01)

            counters = store.counters()
            self.assertEqual(counters["status"], "error")
            self.assertIn("database or disk is full", counters["writer_error"])

            status, health = self._get_health(server.server_address[1])
            self.assertEqual(status, 200)
            self.assertEqual(health["service_status"], "unhealthy")
            self.assertEqual(health["store_status"], "error")
            self.assertIn("database or disk is full", health["store_error"])
            self.assertIn("store_writer_error", health["degraded_reasons"])

            with self.assertRaisesRegex(RuntimeError, "SQLite writer failed"):
                store.flush()
            with self.assertRaisesRegex(RuntimeError, "SQLite writer failed"):
                store.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            # Clear injected error for clean temp-dir teardown if thread still alive
            store._writer_error = None
            if store._thread.is_alive():
                store._queue.put(None)
                store._thread.join(timeout=2)

    def test_source_error_and_stale_source_surface_in_health(self):
        store = Store(self.db_path)
        engine = Engine(store=store)
        server, thread, source_health = self._start_dashboard(engine, store)
        try:
            def broken_source():
                raise RuntimeError("truncated or unreadable source")
                yield  # pragma: no cover

            _consume(engine, broken_source, store, "broken.pcap", threading.Event(), source_health)
            status, health = self._get_health(server.server_address[1])
            self.assertEqual(status, 200)
            self.assertEqual(health["source_status"], "error")
            self.assertEqual(health["service_status"], "unhealthy")
            self.assertIn("source_error", health["degraded_reasons"])
            self.assertIn("truncated or unreadable source", health["source_error"])

            source_health.packet_received(1_700_000_001.0)
            status, health = self._get_health(server.server_address[1])
            self.assertEqual(status, 200)
            self.assertEqual(health["source_status"], "healthy")
            self.assertEqual(health["service_status"], "healthy")

            with source_health.lock:
                source_health.last_packet_monotonic = time.monotonic() - SOURCE_STALE_AFTER_S - 1.0
            status, health = self._get_health(server.server_address[1])
            self.assertEqual(status, 200)
            self.assertEqual(health["source_status"], "stale")
            self.assertEqual(health["service_status"], "degraded")
            self.assertIn("source_stale", health["degraded_reasons"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            store.close()

    def test_wal_safe_backup_and_recovery_preserves_open_incidents(self):
        backup_path = os.path.join(self.temp.name, "backups", "copy.db")
        store = Store(self.db_path)
        try:
            open_id = store.add_alert(Alert(100.0, "port_scan", "high", "10.0.0.1", "scan 1", "10.0.0.2"))
            closed_id = store.add_alert(Alert(100.0, "syn_flood", "high", "10.0.0.9", "flood", "10.0.0.2"))
            store.set_incident_status(closed_id, "closed", "resolved")
            store.record_capture("one.pcap", 10, 600, 0, 100.0, 105.0, 0)

            with self.assertRaises(ValueError):
                store.backup(self.db_path)

            bad_dest = os.path.join(self.temp.name, "missing_dir_as_file")
            Path(bad_dest).write_text("not a dir", encoding="utf-8")
            with self.assertRaises(Exception):
                store.backup(os.path.join(bad_dest, "fail.db"))
            # Active store remains healthy after failed backup attempt
            self.assertEqual(store.counters()["status"], "ok")

            result_path = store.backup(backup_path)
            self.assertEqual(result_path, backup_path)
        finally:
            store.close()

        conn = sqlite3.connect(backup_path)
        try:
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            conn.close()

        restored = Store(backup_path)
        try:
            grouped_id = restored.add_alert(
                Alert(110.0, "port_scan", "critical", "10.0.0.1", "scan 2", "10.0.0.2")
            )
            self.assertEqual(grouped_id, open_id)
            self.assertEqual(restored.get_incident(open_id)["count"], 2)
            self.assertEqual(restored.get_incident(closed_id)["status"], "closed")
            self.assertEqual(restored.capture_summary()["packets"], 10)
        finally:
            restored.close()

    def test_retention_prune_removes_expired_closed_data_and_preserves_open(self):
        store = Store(self.db_path)
        try:
            open_old = store.add_alert(Alert(100.0, "port_scan", "high", "10.0.0.1", "open old", "10.0.0.2"))
            ack_old = store.add_alert(Alert(100.0, "arp_spoof", "medium", "aa:bb:cc:dd:ee:ff", "ack old", "10.0.0.3"))
            store.set_incident_status(ack_old, "acknowledged", "reviewing")
            closed_old = store.add_alert(Alert(100.0, "syn_flood", "high", "10.0.0.8", "closed old", "10.0.0.2"))
            store.set_incident_status(closed_old, "closed", "done")
            closed_recent = store.add_alert(Alert(1000.0, "syn_flood", "high", "10.0.0.9", "closed new", "10.0.0.2"))
            store.set_incident_status(closed_recent, "closed", "done")
            log_old = Alert(100.0, "dns_tunnel", "low", "10.0.0.5", "old log")
            log_old._action = "log"
            store.add_alert(log_old)
            store.add_minute_stat({"t": 100.0, "packets": 5, "bytes": 300, "syn": 1, "dns": 0, "sources": 1})
            store.add_minute_stat({"t": 1000.0, "packets": 6, "bytes": 360, "syn": 1, "dns": 0, "sources": 1})
            store.record_capture("old.pcap", 5, 300, 0, 90.0, 100.0, 0)
            store.record_capture("new.pcap", 6, 360, 0, 990.0, 1000.0, 0)

            deleted = store.prune_older_than(500.0)
            self.assertEqual(deleted, {
                "incidents": 1,
                "alerts": 2,
                "audit_log": 1,
                "minute_stats": 1,
                "capture_runs": 1,
            })
            self.assertIsNotNone(store.get_incident(open_old))
            self.assertIsNotNone(store.get_incident(ack_old))
            self.assertIsNone(store.get_incident(closed_old))
            self.assertIsNotNone(store.get_incident(closed_recent))
            self.assertEqual(len(store.minute_stats(0, 2000)), 1)
            self.assertEqual(store.capture_summary()["runs"], 1)
        finally:
            store.close()

    def test_cli_store_backup_and_prune(self):
        store = Store(self.db_path)
        try:
            closed_old = store.add_alert(Alert(10.0, "syn_flood", "high", "10.0.0.8", "very old", "10.0.0.2"))
            store.set_incident_status(closed_old, "closed", "resolved")
            open_recent = store.add_alert(Alert(time.time(), "port_scan", "high", "10.0.0.1", "recent", "10.0.0.2"))
            store.flush()
        finally:
            store.close()

        backup_path = os.path.join(self.temp.name, "cli-backup.db")
        backup_res = subprocess.run(
            [sys.executable, "-m", "packetlens", "store", "backup", "--db", self.db_path, "--out", backup_path],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(backup_res.returncode, 0, backup_res.stderr)
        self.assertTrue(os.path.isfile(backup_path))

        prune_res = subprocess.run(
            [sys.executable, "-m", "packetlens", "store", "prune", "--db", self.db_path, "--days", "90"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(prune_res.returncode, 0, prune_res.stderr)
        payload = json.loads(prune_res.stdout)
        self.assertEqual(payload["deleted"]["incidents"], 1)

        reopened = Store(self.db_path)
        try:
            self.assertIsNone(reopened.get_incident(closed_old))
            self.assertIsNotNone(reopened.get_incident(open_recent))
        finally:
            reopened.close()

    def test_high_cardinality_load_stays_bounded(self):
        engine = Engine(store=Store(self.db_path))
        try:
            total = 25000
            for idx in range(total):
                a = 10
                b = (idx >> 8) & 0xFF
                c = idx & 0xFF
                src = f"{a}.{b}.{c}.1"
                dst = f"172.16.{b}.{c}"
                frame = synth.tcp_frame(src, dst, 40000 + (idx % 1000), 1000 + (idx % 500), SYN)
                engine.process(1_700_000_000.0 + idx * 0.001, frame)
            engine.finish()
            snap = engine.snapshot()
            self.assertEqual(snap["total_packets"], total)
            self.assertEqual(snap["malformed"], 0)
            self.assertLessEqual(len(engine.talkers), 20000)
            self.assertLessEqual(len(engine.hosts._hosts), HostTable.MAX_HOSTS)
            for det in engine.packet_detectors:
                if isinstance(det, PortScanDetector):
                    self.assertLessEqual(len(det._state), PortScanDetector.MAX_SOURCES)
                if isinstance(det, HorizontalScanDetector):
                    self.assertLessEqual(len(det._state), HorizontalScanDetector.MAX_KEYS)
        finally:
            engine.store.close()


if __name__ == "__main__":
    unittest.main()
