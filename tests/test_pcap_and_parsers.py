import os
import struct
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from packetlens import synth
from packetlens.parsers import ACK, SYN, parse_dns, parse_packet
from packetlens.pcap import PcapError, PcapReader, PcapWriter


ROOT = Path(__file__).resolve().parents[1]


class PcapTests(unittest.TestCase):
    def _temporary_capture_path(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return os.path.join(directory.name, "capture.pcap")

    def _write_timestamp_capture(self, path, endian, magic, fractions):
        with open(path, "wb") as f:
            f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
            for frac in fractions:
                f.write(struct.pack(endian + "IIII", 100, frac, 0, 0))

    def test_roundtrip(self):
        path = self._temporary_capture_path()
        frames = [(1700000000.25, b"abc"), (1700000001.5, b"defgh")]
        with PcapWriter(path) as w:
            for ts, d in frames:
                w.write(ts, d)
        with PcapReader(path) as r:
            out = list(r)
            self.assertEqual(r.linktype, 1)
        self.assertEqual([d for _, d in out], [b"abc", b"defgh"])
        self.assertAlmostEqual(out[0][0], 1700000000.25, places=5)

    def test_version_2_4_is_valid_in_both_byte_orders(self):
        formats = (
            ("little-endian", "<", 0xA1B2C3D4),
            ("big-endian", ">", 0xA1B2C3D4),
        )
        for label, endian, magic in formats:
            with self.subTest(format=label):
                path = self._temporary_capture_path()
                with open(path, "wb") as f:
                    f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
                with PcapReader(path) as reader:
                    self.assertEqual(list(reader), [])

    def test_unsupported_version_is_rejected_before_reading_records(self):
        class TrackingStream(BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                return super().read(size)

        formats = (
            ("little-endian", "<", 0xA1B2C3D4),
            ("big-endian", ">", 0xA1B2C3D4),
        )
        versions = ((1, 4), (2, 5))
        for label, endian, magic in formats:
            for major, minor in versions:
                with self.subTest(format=label, version=f"{major}.{minor}"):
                    stream = TrackingStream(
                        struct.pack(
                            endian + "IHHiIII", magic, major, minor, 0, 0, 65535, 1
                        )
                        + struct.pack(endian + "IIII", 1, 0, 0, 0)
                    )
                    with patch("builtins.open", return_value=stream):
                        with self.assertRaisesRegex(
                            PcapError,
                            f"unsupported classic pcap version {major}.{minor}",
                        ):
                            PcapReader("unused.pcap")
                    self.assertEqual(stream.read_sizes, [24])

    def test_big_endian_nanosecond_file(self):
        """Same data written big-endian with nanosecond timestamps must read identically."""
        path = self._temporary_capture_path()
        with open(path, "wb") as f:
            f.write(struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
            f.write(struct.pack(">IIII", 100, 500_000_000, 3, 3) + b"xyz")
        with PcapReader(path) as r:
            ts, data = next(iter(r))
        self.assertEqual(data, b"xyz")
        self.assertAlmostEqual(ts, 100.5)

    def test_timestamp_fraction_at_resolution_upper_bound_is_valid(self):
        formats = (
            ("little-endian microsecond", "<", 0xA1B2C3D4, 1_000_000),
            ("big-endian microsecond", ">", 0xA1B2C3D4, 1_000_000),
            ("little-endian nanosecond", "<", 0xA1B23C4D, 1_000_000_000),
            ("big-endian nanosecond", ">", 0xA1B23C4D, 1_000_000_000),
        )
        for label, endian, magic, resolution in formats:
            with self.subTest(format=label):
                path = self._temporary_capture_path()
                self._write_timestamp_capture(
                    path, endian, magic, [resolution - 1]
                )
                with PcapReader(path) as reader:
                    self.assertEqual(
                        list(reader), [(100 + (resolution - 1) / resolution, b"")]
                    )

    def test_timestamp_fraction_at_resolution_limit_is_rejected(self):
        formats = (
            ("little-endian microsecond", "<", 0xA1B2C3D4, 1_000_000),
            ("big-endian microsecond", ">", 0xA1B2C3D4, 1_000_000),
            ("little-endian nanosecond", "<", 0xA1B23C4D, 1_000_000_000),
            ("big-endian nanosecond", ">", 0xA1B23C4D, 1_000_000_000),
        )
        for label, endian, magic, resolution in formats:
            with self.subTest(format=label):
                path = self._temporary_capture_path()
                self._write_timestamp_capture(path, endian, magic, [0, resolution])
                with PcapReader(path) as reader:
                    records = iter(reader)
                    self.assertEqual(next(records), (100.0, b""))
                    with self.assertRaisesRegex(PcapError, "timestamp fraction"):
                        next(records)

    def test_rejects_non_pcap(self):
        path = self._temporary_capture_path()
        with open(path, "wb") as f:
            f.write(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)             # pcapng magic
        with self.assertRaises(PcapError):
            PcapReader(path)

    def test_empty_capture_is_valid(self):
        path = self._temporary_capture_path()
        with PcapWriter(path):
            pass
        with PcapReader(path) as r:
            self.assertEqual(list(r), [])

    def test_truncated_record_header_raises(self):
        path = self._temporary_capture_path()
        with PcapWriter(path) as w:
            w.write(1.0, b"abcdef")
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[:32])
        with PcapReader(path) as r:
            with self.assertRaisesRegex(PcapError, "truncated pcap record header"):
                list(r)

    def test_truncated_packet_data_raises(self):
        path = self._temporary_capture_path()
        with PcapWriter(path) as w:
            w.write(1.0, b"abcdef")
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[:-3])
        with PcapReader(path) as r:
            with self.assertRaisesRegex(PcapError, "truncated pcap packet data"):
                list(r)

    def test_captured_length_exceeding_original_length_raises(self):
        path = self._temporary_capture_path()
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 4, 1))
            f.write(struct.pack("<IIII", 1, 0, 5, 4))
        with PcapReader(path) as r:
            with self.assertRaisesRegex(
                PcapError, "captured length 5 exceeds original length 4"
            ):
                list(r)

    def test_captured_length_equal_to_snaplen_is_valid(self):
        path = self._temporary_capture_path()
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 3, 1))
            f.write(struct.pack("<IIII", 1, 0, 3, 3) + b"xyz")
        with PcapReader(path) as r:
            self.assertEqual(list(r), [(1.0, b"xyz")])

    def test_captured_length_exceeding_snaplen_raises_before_payload_read(self):
        class TrackingStream(BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                return super().read(size)

        stream = TrackingStream(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 4, 1)
            + struct.pack("<IIII", 1, 0, 5, 5)
        )
        with patch("builtins.open", return_value=stream):
            reader = PcapReader("unused.pcap")
        self.addCleanup(reader.close)
        with self.assertRaisesRegex(PcapError, "captured length 5 exceeds snaplen 4"):
            list(reader)
        self.assertEqual(stream.read_sizes, [24, 16])

    def test_captured_length_smaller_than_original_length_is_valid(self):
        path = self._temporary_capture_path()
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 3, 1))
            f.write(struct.pack("<IIII", 1, 0, 3, 5) + b"xyz")
        with PcapReader(path) as r:
            self.assertEqual(list(r), [(1.0, b"xyz")])

    def test_writer_rejects_packet_larger_than_snaplen(self):
        path = self._temporary_capture_path()
        with PcapWriter(path, snaplen=3) as writer:
            with self.assertRaisesRegex(PcapError, "packet length 4 exceeds snaplen 3"):
                writer.write(1.0, b"abcd")

    def test_zero_snaplen_retains_existing_unbounded_behavior(self):
        path = self._temporary_capture_path()
        with PcapWriter(path, snaplen=0) as writer:
            writer.write(1.0, b"longer than zero")
        with PcapReader(path) as reader:
            self.assertEqual(list(reader), [(1.0, b"longer than zero")])


class UnsupportedLinkTypeCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pcap = os.path.join(self.temp.name, "unsupported-linktype.pcap")
        with PcapWriter(self.pcap, linktype=999):
            pass

    def _assert_cli_rejects_capture(self, command):
        result = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, timeout=30
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "Unsupported link type 999. Supported: Ethernet (1) and Linux cooked (113).",
            result.stderr,
        )

    def test_analyze_rejects_unsupported_link_type(self):
        self._assert_cli_rejects_capture(
            [sys.executable, "-m", "packetlens", "analyze", self.pcap]
        )

    def test_serve_rejects_unsupported_link_type(self):
        db = os.path.join(self.temp.name, "serve.db")
        self._assert_cli_rejects_capture(
            [
                sys.executable, "-m", "packetlens", "serve", "--pcap", self.pcap,
                "--db", db,
            ]
        )


class ParserTests(unittest.TestCase):
    def test_tcp_syn(self):
        f = synth.tcp_frame("10.0.0.1", "10.0.0.2", 12345, 443, SYN)
        p = parse_packet(1.0, f)
        self.assertEqual((p.src, p.dst, p.sport, p.dport, p.proto), ("10.0.0.1", "10.0.0.2", 12345, 443, 6))
        self.assertTrue(p.is_syn_only)

    def test_syn_ack_is_not_syn_only(self):
        p = parse_packet(1.0, synth.tcp_frame("10.0.0.2", "10.0.0.1", 443, 12345, SYN | ACK))
        self.assertFalse(p.is_syn_only)

    def test_payload_length_and_ethernet_padding(self):
        f = synth.tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, ACK, payload=b"x" * 10)
        self.assertEqual(parse_packet(1.0, f).payload_len, 10)
        self.assertEqual(parse_packet(1.0, f + b"\0" * 6).payload_len, 10)   # padding ignored

    def test_ip_checksum_valid(self):
        f = synth.tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, SYN)
        self.assertEqual(synth.checksum(f[14:34]), 0)     # a correct header sums to zero

    def test_dns_query_and_response(self):
        q = parse_packet(1.0, synth.dns_frame("10.0.0.1", "10.0.0.53", 4000, 53, 7, "WWW.Example.com"))
        self.assertEqual(q.dns, ("www.example.com", 1, False))
        r = parse_packet(1.0, synth.dns_frame("10.0.0.53", "10.0.0.1", 53, 4000, 7, "a.b.c", response=True))
        self.assertEqual(r.dns, ("a.b.c", 1, True))

    def test_arp(self):
        f = synth.arp_frame(2, "10.0.0.1", synth.mac_for("10.0.0.1"), "10.0.0.9", b"\0" * 6)
        p = parse_packet(1.0, f)
        self.assertEqual(p.arp, (2, synth.mac_for("10.0.0.1"), "10.0.0.1"))

    def test_icmp(self):
        self.assertEqual(parse_packet(1.0, synth.icmp_echo_frame("10.0.0.1", "10.0.0.2", 1)).icmp_type, 8)

    def test_garbage_and_truncation_never_crash(self):
        good = synth.tcp_frame("10.0.0.1", "10.0.0.2", 1, 2, SYN)
        for n in range(len(good)):
            parse_packet(1.0, good[:n])                    # must return a Packet or None, never raise
        for junk in (b"", b"\xff" * 5, bytes(range(60))):
            parse_packet(1.0, junk)

    def test_dns_name_pointer_rejected(self):
        self.assertIsNone(parse_dns(b"\0" * 4 + b"\x00\x01" + b"\0" * 6 + b"\xc0\x0c"))


if __name__ == "__main__":
    unittest.main()
