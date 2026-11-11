import os
import struct
import tempfile
import unittest

from packetlens import synth
from packetlens.parsers import ACK, SYN, parse_dns, parse_packet
from packetlens.pcap import PcapError, PcapReader, PcapWriter


class PcapTests(unittest.TestCase):
    def _temporary_capture_path(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return os.path.join(directory.name, "capture.pcap")

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
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            f.write(struct.pack("<IIII", 1, 0, 5, 4))
        with PcapReader(path) as r:
            with self.assertRaisesRegex(
                PcapError, "captured length 5 exceeds original length 4"
            ):
                list(r)

    def test_captured_length_smaller_than_original_length_is_valid(self):
        path = self._temporary_capture_path()
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            f.write(struct.pack("<IIII", 1, 0, 3, 6) + b"xyz")
        with PcapReader(path) as r:
            self.assertEqual(list(r), [(1.0, b"xyz")])


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
