import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from packetlens import synth
from packetlens.detectors import Alert, HorizontalScanDetector
from packetlens.engine import Engine
from packetlens.hosts import HostTable
from packetlens.parsers import SYN, parse_packet
from packetlens.policy import Policy, default_policy_path, load_policy, validate_policy
from packetlens.pcap import PcapWriter
from packetlens.store import Store


ROOT = Path(__file__).resolve().parents[1]


def valid_policy(policies=None, gap=300):
    return {"version": 1, "name": "tests", "incident_gap_s": gap,
            "policies": policies if policies is not None else [{
                "id": "horizontal", "detector": "horizontal_scan", "enabled": True,
                "action": "alert", "params": {}, "allowlist": {"src": [], "dst": []}}]}


class PolicyTests(unittest.TestCase):
    def test_validation_collects_all_schema_errors(self):
        broken = {
            "version": "1", "name": "", "incident_gap_s": 0, "policies": [
                {"id": "duplicate", "detector": "horizontal_scan", "enabled": "yes", "action": "email",
                 "severity": [], "params": {"mystery": 3, "min_hosts": "bad"},
                 "allowlist": {"src": ["not-an-ip"], "dst": "10.0.0.1"}},
                {"id": "duplicate", "detector": "horizontal_scan", "enabled": True,
                 "action": "alert", "params": {"min_hosts": 0}},
                {"id": "unknown-rule", "detector": "unknown", "enabled": True, "action": "alert"},
            ],
        }
        errors = validate_policy(broken)
        expected_paths = ("$.version", "$.name", "$.incident_gap_s", "$.policies[0].enabled",
                          "$.policies[0].action", "$.policies[0].severity",
                          "$.policies[0].params.mystery", "$.policies[0].params.min_hosts",
                          "$.policies[0].allowlist.src[0]", "$.policies[0].allowlist.dst",
                          "$.policies[1].id", "$.policies[1].params.min_hosts",
                          "$.policies[2].detector")
        for path in expected_paths:
            self.assertTrue(any(error.startswith(path + ":") for error in errors), (path, errors))
        with self.assertRaisesRegex(ValueError, r"Invalid policy:"):
            Policy(broken)

    def test_default_policy_validates(self):
        self.assertEqual(validate_policy(json.loads(default_policy_path().read_text(encoding="utf-8"))), [])
        self.assertEqual(load_policy(default_policy_path()).incident_gap_s, 300)

    def test_per_policy_incident_gap_validation_and_loading(self):
        policy = valid_policy()
        policy["policies"][0]["incident_gap_s"] = 12.5
        self.assertEqual(validate_policy(policy), [])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            for gap in (0, -1, "15", True):
                policy["policies"][0]["incident_gap_s"] = gap
                path.write_text(json.dumps(policy), encoding="utf-8")
                with self.assertRaisesRegex(
                        ValueError, r"\$\.policies\[0\]\.incident_gap_s:"):
                    load_policy(path)

    def test_allowlist_suppresses_source_cidr_and_placeholder_does_not_match(self):
        policy = valid_policy([{
            "id": "horizontal", "detector": "horizontal_scan", "enabled": True, "action": "alert",
            "params": {}, "allowlist": {"src": ["192.168.1.0/24", "many", "-"], "dst": []}}])
        engine = Engine(policy=policy)
        frames, events = synth.generate(300, seed=8, attacks=True)
        alerts = []
        for ts, frame in frames:
            alerts.extend(engine.process(ts, frame))
        alerts.extend(engine.finish())
        self.assertFalse(any(alert.kind == "horizontal_scan" for alert in alerts))

    def test_default_policy_preserves_detector_alerts_on_attack_run(self):
        frames, _ = synth.generate(300, seed=8, attacks=True)
        plain, configured = Engine(), Engine(policy=load_policy(default_policy_path()))
        left, right = [], []
        for ts, frame in frames:
            left.extend(plain.process(ts, frame))
            right.extend(configured.process(ts, frame))
        left.extend(plain.finish())
        right.extend(configured.finish())
        core = lambda alert: (alert.ts, alert.kind, alert.severity, alert.src, alert.detail,
                              alert.dst, alert.data)
        self.assertEqual([core(alert) for alert in left], [core(alert) for alert in right])


class HorizontalScanTests(unittest.TestCase):
    def test_synthetic_horizontal_attack_detected_but_benign_not(self):
        attack_frames, attack_events = synth.generate(300, seed=8, attacks=True)
        benign_frames, _ = synth.generate(300, seed=7, attacks=False)
        self.assertEqual(attack_events[-1]["kind"], "horizontal_scan")
        for frames, should_alert in ((attack_frames, True), (benign_frames, False)):
            detector = HorizontalScanDetector()
            alerts = []
            for ts, frame in frames:
                pkt = parse_packet(ts, frame)
                if pkt:
                    alerts.extend(detector.observe(pkt))
            self.assertEqual(bool(alerts), should_alert)
        self.assertEqual(attack_events[-1]["src"], "192.168.1.203")
        self.assertEqual(attack_events[-1]["detects"], "horizontal_scan")


class HostTableTests(unittest.TestCase):
    @staticmethod
    def packet(ts, src, dst):
        return SimpleNamespace(ts=ts, length=60, src=src, dst=dst, proto=6, dport=443,
                               dns=None, ethertype=0)

    def test_lru_host_eviction(self):
        hosts = HostTable(max_hosts=2)
        hosts.update(self.packet(1, "10.0.0.1", "10.0.0.2"))
        hosts.update(self.packet(2, "10.0.0.1", "10.0.0.2"))
        hosts.update(self.packet(3, "10.0.0.3", "10.0.0.4"))
        self.assertEqual({row["ip"] for row in hosts.snapshot()}, {"10.0.0.3", "10.0.0.4"})
        self.assertLessEqual(len(hosts._hosts), 2)

    def test_top_ports_excludes_non_tcp_udp_and_port_zero(self):
        hosts = HostTable()
        hosts.update(parse_packet(1.0, synth.arp_frame(2, "10.0.0.1", synth.mac_for("10.0.0.1"), "10.0.0.2", b"\0" * 6)))
        hosts.update(parse_packet(2.0, synth.icmp_echo_frame("10.0.0.1", "10.0.0.2", 1)))
        hosts.update(SimpleNamespace(ts=3.0, length=60, src="10.0.0.1", dst="10.0.0.2", proto=6, dport=0, dns=None, ethertype=0x0800))
        hosts.update(SimpleNamespace(ts=4.0, length=60, src="10.0.0.1", dst="10.0.0.2", proto=6, dport=443, dns=None, ethertype=0x0800))
        by_ip = {row["ip"]: row for row in hosts.snapshot()}
        self.assertEqual(by_ip["10.0.0.1"]["top_ports"], [[443, 1]])

    def test_dirty_tracking_limits_engine_flush_to_modified_hosts(self):
        hosts = HostTable()
        hosts.update(self.packet(1, "10.0.0.1", "10.0.0.2"))
        self.assertEqual({r["ip"] for r in hosts.snapshot(dirty_only=True)}, {"10.0.0.1", "10.0.0.2"})
        hosts.clear_dirty()
        self.assertEqual(hosts.snapshot(dirty_only=True), [])
        hosts.update(self.packet(2, "10.0.0.3", "10.0.0.4"))
        hosts.record_alert("10.0.0.1")
        self.assertEqual({r["ip"] for r in hosts.snapshot(dirty_only=True)}, {"10.0.0.1", "10.0.0.3", "10.0.0.4"})

        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "dirty.db"))
            try:
                engine = Engine(store=store)
                calls = []
                orig_upsert = store.upsert_hosts

                def spy(rows):
                    calls.append([r["ip"] for r in rows])
                    return orig_upsert(rows)

                store.upsert_hosts = spy
                engine.process(1.0, synth.tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, SYN))
                engine.process(15.0, synth.tcp_frame("10.0.0.3", "10.0.0.4", 1235, 443, SYN))
                engine.process(16.0, synth.tcp_frame("10.0.0.5", "10.0.0.6", 1236, 8080, SYN))
                engine.finish()
                self.assertEqual(len(calls), 2)
                self.assertEqual(set(calls[0]), {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"})
                self.assertEqual(set(calls[1]), {"10.0.0.5", "10.0.0.6"})
            finally:
                store.close()


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "store.db")
        self.store = Store(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_incident_grouping_status_workflow_hosts_stats_and_escaped_search(self):
        first = self.store.add_alert(Alert(100, "port_scan", "high", "10.0.0.1", "port scan",
                                           "10.0.0.2", data={"ports": 60}))
        grouped = self.store.add_alert(Alert(110, "port_scan", "critical", "10.0.0.1", "again",
                                             "10.0.0.2", data={"ports": 80}))
        self.assertEqual(first, grouped)
        self.store.add_alert(Alert(500, "port_scan", "high", "10.0.0.1", "later", "10.0.0.2"))
        result = self.store.list_incidents()
        self.assertEqual(result["total"], 2)
        incident = self.store.get_incident(first)
        self.assertEqual(incident["count"], 2)
        self.assertEqual(incident["severity"], "critical")
        self.assertEqual(len(incident["alerts"]), 2)
        self.assertEqual(self.store.list_incidents(q="%_")[ "total"], 0)
        self.assertEqual(self.store.set_incident_status(first, "acknowledged", "triaged")["status"],
                         "acknowledged")
        self.assertEqual(self.store.set_incident_status(first, "closed", "resolved")["status"], "closed")
        with self.assertRaises(ValueError):
            self.store.set_incident_status(first, "acknowledged")
        reopened = self.store.add_alert(Alert(501, "port_scan", "high", "10.0.0.1", "new incident",
                                              "10.0.0.2"))
        self.assertNotEqual(reopened, first)
        self.store.upsert_hosts([{
            "ip": "10.0.0.1", "first_seen": 90, "last_seen": 501, "packets_in": 1,
            "packets_out": 4, "bytes_in": 60, "bytes_out": 240, "peers": ["10.0.0.2"],
            "peers_truncated": False, "top_ports": [[443, 4]],
            "protocols": {"TCP": 5}, "alert_count": 3,
        }])
        self.store.add_minute_stat({"t": 100, "packets": 5, "bytes": 300, "syn": 2, "dns": 1, "sources": 3})
        self.store.flush()
        host = self.store.get_host("10.0.0.1")
        self.assertEqual(set(host["related_incident_ids"]), {first, reopened})
        self.assertEqual(self.store.list_hosts(q="10.0.0.%")["total"], 0)
        self.assertEqual(self.store.minute_stats(99, 101)[0]["packets"], 5)
        self.assertEqual(self.store.summary()["total_alerts"], 4)
        self.assertEqual(self.store.set_incident_status(reopened, "closed")["status"], "closed")
        after_close = self.store.add_alert(Alert(502, "port_scan", "high", "10.0.0.1", "after close",
                                                 "10.0.0.2"))
        self.assertNotEqual(after_close, reopened)
        with self.assertRaises(ValueError):
            self.store.set_incident_status(after_close, "open")

    def test_log_only_alert_does_not_create_incident(self):
        alert = Alert(1, "dns_tunnel", "high", "10.0.0.2", "log only")
        alert._action = "log"
        self.assertIsNone(self.store.add_alert(alert))
        self.assertEqual(self.store.list_incidents()["total"], 0)
        self.assertEqual(self.store.summary()["total_alerts"], 1)

    def test_incident_gaps_split_volumetric_but_preserve_port_scan_grouping(self):
        first_volume = self.store.add_alert(
            Alert(1000, "volumetric", "high", "-", "first volume alert"))
        next_volume = self.store.add_alert(
            Alert(1025, "volumetric", "high", "-", "separate volume alert"))
        self.assertNotEqual(first_volume, next_volume)

        close_volume = self.store.add_alert(
            Alert(2000, "volumetric", "high", "-", "first nearby volume alert"))
        grouped_volume = self.store.add_alert(
            Alert(2005, "volumetric", "high", "-", "nearby volume alert"))
        self.assertEqual(close_volume, grouped_volume)

        first_scan = self.store.add_alert(
            Alert(3000, "port_scan", "high", "10.0.0.1", "first scan"))
        grouped_scan = self.store.add_alert(
            Alert(3100, "port_scan", "high", "10.0.0.1", "same scan"))
        self.assertEqual(first_scan, grouped_scan)

    def test_policy_incident_gap_is_carried_to_store(self):
        policy = valid_policy()
        rule = policy["policies"][0]
        rule["incident_gap_s"] = 10
        first_alert = Alert(4000, "horizontal_scan", "high", "10.0.0.1", "first")
        second_alert = Alert(4020, "horizontal_scan", "high", "10.0.0.1", "later")
        first_alert = Engine._apply_policy([first_alert], rule)[0]
        second_alert = Engine._apply_policy([second_alert], rule)[0]
        first = self.store.add_alert(first_alert)
        second = self.store.add_alert(second_alert)
        self.assertNotEqual(first, second)

    def test_full_queue_drops_and_counts_writes(self):
        self.store.close()
        self.store = Store(self.path, queue_capacity=1)
        entered, release = threading.Event(), threading.Event()
        self.store._enqueue(lambda connection: (entered.set(), release.wait(5)))
        self.assertTrue(entered.wait(2))
        self.store._enqueue(lambda connection: None)
        self.assertIsNone(self.store._enqueue(lambda connection: None))
        self.assertEqual(self.store.counters()["dropped"], 1)
        release.set()
        self.store.flush()
        self.assertGreaterEqual(self.store.counters()["written"], 2)

    def test_host_ip_sort_asc_incident_sort_audit_truncated_and_transient_retry(self):
        # Hosts ip sort ascending
        self.store.upsert_hosts([
            {"ip": "10.0.0.10", "first_seen": 1, "last_seen": 10, "packets_in": 1, "packets_out": 1,
             "bytes_in": 100, "bytes_out": 100, "peers": [], "peers_truncated": False, "top_ports": [],
             "protocols": {}, "alert_count": 0},
            {"ip": "10.0.0.2", "first_seen": 1, "last_seen": 5, "packets_in": 1, "packets_out": 1,
             "bytes_in": 500, "bytes_out": 500, "peers": [], "peers_truncated": False, "top_ports": [],
             "protocols": {}, "alert_count": 0},
        ])
        self.assertEqual([h["ip"] for h in self.store.list_hosts(sort="ip")["items"]], ["10.0.0.10", "10.0.0.2"])
        self.assertEqual([h["ip"] for h in self.store.list_hosts(sort="bytes")["items"]], ["10.0.0.2", "10.0.0.10"])

        # Incident server-side sort & order
        i_low = self.store.add_alert(Alert(100, "arp_spoof", "low", "10.0.0.1", "a"))
        i_crit = self.store.add_alert(Alert(50, "port_scan", "critical", "10.0.0.2", "b"))
        self.assertEqual([x["id"] for x in self.store.list_incidents(sort="severity", order="desc")["items"]],
                         [i_crit, i_low])
        self.assertEqual([x["id"] for x in self.store.list_incidents(sort="severity", order="asc")["items"]],
                         [i_low, i_crit])
        with self.assertRaises(ValueError):
            self.store.list_incidents(sort="unknown")
        with self.assertRaises(ValueError):
            self.store.list_incidents(order="sideways")

        # audit_truncated boolean
        detail = self.store.get_incident(i_low)
        self.assertFalse(detail["audit_truncated"])
        self.store._enqueue(
            lambda conn: conn.executemany(
                "INSERT INTO audit_log(incident_id,ts,action,note) VALUES(?,?,?,?)",
                [(i_low, float(k), "acknowledged", "n") for k in range(205)],
            ),
            wait=True,
        )
        detail = self.store.get_incident(i_low)
        self.assertTrue(detail["audit_truncated"])
        self.assertEqual(len(detail["audit_log"]), 200)

        # Atomic set_incident_status under concurrency
        target_id = self.store.add_alert(Alert(200, "port_scan", "high", "10.0.0.9", "scan"))
        results, errors = [], []
        barrier = threading.Barrier(2)

        def worker(status):
            barrier.wait()
            try:
                results.append(self.store.set_incident_status(target_id, status, "race")["status"])
            except ValueError as exc:
                errors.append(str(exc))

        t1 = threading.Thread(target=worker, args=("closed",))
        t2 = threading.Thread(target=worker, args=("acknowledged",))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(len(results) + len(errors), 2)
        if "closed" in results and len(errors) == 1:
            self.assertIn("invalid incident status transition", errors[0])

        # Transient sqlite3.OperationalError ("database is locked") recovers with retry
        attempts = {"n": 0}

        def flaky_write(_conn):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise sqlite3.OperationalError("database is locked")
            return "recovered"

        self.assertEqual(self.store._enqueue(flaky_write, wait=True), "recovered")
        self.assertEqual(attempts["n"], 3)
        self.assertEqual(self.store.counters()["status"], "ok")


class IntegrationAndCliTests(unittest.TestCase):
    def test_engine_store_end_to_end_and_cli(self):
        frames, _ = synth.generate(300, seed=8, attacks=True)
        with tempfile.TemporaryDirectory() as temp:
            db = os.path.join(temp, "capture.db")
            store = Store(db)
            engine = Engine(store=store, policy=load_policy(default_policy_path()))
            for ts, frame in frames:
                engine.process(ts, frame)
            engine.finish()
            self.assertGreaterEqual(store.list_incidents()["total"], 7)
            volumetric_incidents = store.list_incidents(kind="volumetric")["items"]
            ranges = [
                (round(item["first_ts"] - synth.BASE_TS, 1),
                 round(item["last_ts"] - synth.BASE_TS, 1))
                for item in sorted(volumetric_incidents, key=lambda row: row["first_ts"])
            ]
            self.assertEqual(ranges, [
                (45.0, 45.0), (70.0, 70.0), (200.0, 200.0),
                (230.0, 230.0), (270.0, 270.0),
            ])
            self.assertTrue(store.list_hosts()["items"])
            self.assertTrue(store.minute_stats(0, 1_800_000_000))
            store.close()

            pcap = os.path.join(temp, "small.pcap")
            with PcapWriter(pcap) as writer:
                writer.write(1.0, synth.tcp_frame("10.0.0.1", "10.0.0.2", 50000, 443, SYN))
            commands = [
                [sys.executable, "-m", "packetlens", "policy", "validate", str(default_policy_path())],
                [sys.executable, "-m", "packetlens", "analyze", pcap, "--policy",
                 str(default_policy_path()), "--db", db],
                [sys.executable, "-m", "packetlens", "incidents", "list", "--db", db],
            ]
            for command in commands:
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
