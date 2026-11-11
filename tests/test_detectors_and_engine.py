import unittest

from packetlens import synth
from packetlens.detectors import (ArpSpoofDetector, DnsTunnelDetector, PortScanDetector, SynFloodDetector,
                                  shannon_entropy, split_domain)
from packetlens.engine import Engine
from packetlens.evaluate import evaluate
from packetlens.parsers import ACK, SYN, parse_packet
from packetlens.timeseries import BinAggregator, EwmaZScoreDetector


def pkt(frame, ts):
    return parse_packet(ts, frame)


class HelperTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)

    def test_split_domain(self):
        self.assertEqual(split_domain("a.b.example.com"), ("a.b", "example.com"))
        self.assertEqual(split_domain("x.example.co.uk"), ("x", "example.co.uk"))
        self.assertEqual(split_domain("example.com"), ("", "example.com"))


class DetectorTests(unittest.TestCase):
    def test_port_scan_fires_once_and_not_for_normal_client(self):
        d, alerts = PortScanDetector(), []
        for i in range(40):
            alerts += d.observe(pkt(synth.tcp_frame("10.0.0.9", "10.0.0.1", 5000, 1000 + i, SYN), 100 + i * 0.1))
        self.assertEqual(len(alerts), 1)
        d = PortScanDetector()
        for i in range(200):          # same port, many connections: a busy client, not a scan
            self.assertEqual(list(d.observe(pkt(synth.tcp_frame("10.0.0.9", "10.0.0.1", 5000 + i, 443, SYN), 100 + i * 0.05))), [])

    def test_scan_ignores_non_syn(self):
        d = PortScanDetector()
        for i in range(100):
            self.assertEqual(list(d.observe(pkt(synth.tcp_frame("10.0.0.9", "10.0.0.1", 1, 1000 + i, ACK), 100 + i * 0.01))), [])

    def test_syn_flood_vs_fast_scan(self):
        d, flood = SynFloodDetector(threshold=100), []
        for i in range(150):
            flood += d.observe(pkt(synth.tcp_frame(f"1.1.{i // 250}.{i % 250 + 1}", "10.0.0.1", 5000, 80, SYN), 200 + i * 0.001))
        self.assertEqual(len(flood), 1)
        d = SynFloodDetector(threshold=100)
        for i in range(500):          # one SYN per port: that is a scan, not a flood
            self.assertEqual(list(d.observe(pkt(synth.tcp_frame("9.9.9.9", "10.0.0.1", 5000, 1000 + i, SYN), 200 + i * 0.001))), [])

    def test_dns_tunnel_and_normal_dns(self):
        d, alerts = DnsTunnelDetector(), []
        for i in range(30):
            name = "".join("abcdefghijklmnopqrstuvwxyz234567"[(i * 7 + j * 11) % 32] for j in range(30)) + ".t.evil.com"
            alerts += d.observe(pkt(synth.dns_frame("10.0.0.5", "10.0.0.53", 4000, 53, i, name), 10 + i))
        self.assertTrue(alerts)
        d = DnsTunnelDetector()
        for i in range(60):
            self.assertEqual(list(d.observe(pkt(synth.dns_frame("10.0.0.5", "10.0.0.53", 4000, 53, i, f"www{i % 3}.google.com"), 10 + i))), [])

    def test_arp_spoof(self):
        d = ArpSpoofDetector()
        gw = "10.0.0.1"
        real = pkt(synth.arp_frame(2, gw, synth.mac_for(gw), "10.0.0.9", b"\0" * 6), 1)
        fake = pkt(synth.arp_frame(2, gw, synth.mac_for("10.0.0.66"), "10.0.0.9", b"\0" * 6), 2)
        self.assertEqual(list(d.observe(real)), [])
        self.assertEqual(len(d.observe(fake)), 1)
        self.assertEqual(list(d.observe(real)), [])         # flip back inside cooldown: no alert storm


class TimeSeriesTests(unittest.TestCase):
    def test_bins_fill_gaps_with_zeros(self):
        agg, out = BinAggregator(), []
        for ts in (100.2, 100.7, 103.1):
            out += agg.add(pkt(synth.tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, ACK), ts))
        out += agg.flush()
        self.assertEqual([b["packets"] for b in out], [2, 0, 0, 1])

    def test_zscore_flags_spike_once_and_adapts(self):
        z, alerts = EwmaZScoreDetector(), []
        for t in range(60):
            alerts += z.update({"t": t, "packets": 100 + (t % 5), "bytes": 5000, "syn": 5, "dns": 5, "sources": 10})
        self.assertEqual(alerts, [])
        for t in range(60, 65):
            alerts += z.update({"t": t, "packets": 2000, "bytes": 5000, "syn": 5, "dns": 5, "sources": 10})
        self.assertEqual(len(alerts), 1)


class EndToEndTests(unittest.TestCase):
    def test_generated_traffic_has_no_malformed_packets(self):
        frames, _ = synth.generate(60, seed=2, attacks=False)
        e = Engine()
        for ts, d in frames:
            e.process(ts, d)
        self.assertEqual(e.malformed, 0)
        self.assertEqual(e.total_packets, len(frames))

    def test_all_scripted_attacks_detected(self):
        r = evaluate(300)
        self.assertTrue(all(row["detected"] for row in r["events"]), r["events"])
        self.assertLessEqual(r["false_positives_per_hour"], 30)


if __name__ == "__main__":
    unittest.main()
