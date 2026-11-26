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

    def test_writer_accepts_supported_link_types(self):
        for linktype in (1, 113):
            with self.subTest(linktype=linktype):
                path = self._temporary_capture_path()
                with PcapWriter(path, linktype=linktype):
                    pass
                with open(path, "rb") as capture:
                    global_header = struct.unpack("<IHHiIII", capture.read(24))
                self.assertEqual(global_header[6], linktype)

    def test_writer_rejects_unsupported_link_types_before_creating_file(self):
        for linktype in (0, 999):
            with self.subTest(linktype=linktype):
                path = self._temporary_capture_path()
                with self.assertRaisesRegex(
                    PcapError, f"Unsupported link type {linktype}"
                ):
                    PcapWriter(path, linktype=linktype)
                self.assertFalse(os.path.exists(path))

    def test_unsupported_link_type_is_rejected_before_record_reads(self):
        class TrackingStream(BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                return super().read(size)

        stream = TrackingStream(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 999)
            + struct.pack("<IIII", 1, 0, 0, 0)
        )
        with patch("builtins.open", return_value=stream):
            with self.assertRaisesRegex(PcapError, "Unsupported link type 999"):
                PcapReader("unused.pcap")
        self.assertEqual(stream.read_sizes, [24])

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
        with open(path, "rb") as capture:
            global_header = struct.unpack("<IHHiIII", capture.read(24))
        self.assertEqual(global_header[5], 0)
        with PcapReader(path) as reader:
            self.assertEqual(list(reader), [(1.0, b"longer than zero")])


class UnsupportedLinkTypeCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pcap = os.path.join(self.temp.name, "unsupported-linktype.pcap")
        with open(self.pcap, "wb") as capture:
            capture.write(
                struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 999)
            )

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

    def test_stacked_vlan_and_qinq_up_to_four_tags(self):
        inner = synth.ipv4("10.0.0.1", "10.0.0.2", 6, struct.pack("!HHIIHHHH", 1234, 80, 0, 0, (5 << 12) | SYN, 65535, 0, 0))
        eth_hdr = synth.mac_for("10.0.0.2") + synth.mac_for("10.0.0.1")

        # 2 stacked tags: 802.1ad (0x88A8) + 802.1Q (0x8100)
        qinq = eth_hdr + struct.pack("!HHHHH", 0x88A8, 100, 0x8100, 200, 0x0800) + inner
        pkt_qinq = parse_packet(1.0, qinq)
        self.assertIsNotNone(pkt_qinq)
        self.assertEqual((pkt_qinq.src, pkt_qinq.dst, pkt_qinq.dport), ("10.0.0.1", "10.0.0.2", 80))

        # 4 stacked tags: valid upper bound
        four = eth_hdr + (struct.pack("!HH", 0x8100, 1) * 4) + struct.pack("!H", 0x0800) + inner
        pkt_four = parse_packet(1.0, four)
        self.assertIsNotNone(pkt_four)
        self.assertEqual(pkt_four.dport, 80)

        # 5 stacked tags: rejected safely
        five = eth_hdr + (struct.pack("!HH", 0x8100, 1) * 5) + struct.pack("!H", 0x0800) + inner
        self.assertIsNone(parse_packet(1.0, five))

        # Linux SLL (linktype 113) with 802.1Q tag
        sll_vlan = b"\x00" * 14 + struct.pack("!HHH", 0x8100, 42, 0x0800) + inner
        pkt_sll = parse_packet(1.0, sll_vlan, linktype=113)
        self.assertIsNotNone(pkt_sll)
        self.assertEqual(pkt_sll.dport, 80)

    def test_ipv6_extension_headers_and_fragment_handling(self):
        import socket
        src6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        dst6 = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        tcp = struct.pack("!HHIIHHHH", 5555, 443, 1, 0, (5 << 12) | SYN, 65535, 0, 0)
        eth_hdr = synth.mac_for("10.0.0.2") + synth.mac_for("10.0.0.1") + struct.pack("!H", 0x86DD)

        # Hop-by-Hop (0) -> Destination Options (60) -> Routing (43) -> TCP (6)
        hbh = struct.pack("!BB6s", 60, 0, b"\0" * 6)
        dst_opt = struct.pack("!BB6s", 43, 0, b"\0" * 6)
        routing = struct.pack("!BB6s", 6, 0, b"\0" * 6)
        payload = hbh + dst_opt + routing + tcp
        v6_hdr = struct.pack("!IHBB", 6 << 28, len(payload), 0, 64) + src6 + dst6
        pkt = parse_packet(1.0, eth_hdr + v6_hdr + payload)
        self.assertIsNotNone(pkt)
        self.assertEqual((pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport),
                         ("2001:db8::1", "2001:db8::2", 6, 5555, 443))
        self.assertTrue(pkt.is_syn_only)

        # Fragment header (44): first fragment (offset 0) parses transport; non-first skips transport
        frag_first = struct.pack("!BBHI", 6, 0, 0x0001, 99) + tcp
        v6_first = struct.pack("!IHBB", 6 << 28, len(frag_first), 44, 64) + src6 + dst6
        pkt_first = parse_packet(1.0, eth_hdr + v6_first + frag_first)
        self.assertEqual(pkt_first.dport, 443)

        frag_next = struct.pack("!BBHI", 6, 0, 0x0018, 99) + b"fragment-body-data-here"
        v6_next = struct.pack("!IHBB", 6 << 28, len(frag_next), 44, 64) + src6 + dst6
        pkt_next = parse_packet(1.0, eth_hdr + v6_next + frag_next)
        self.assertIsNotNone(pkt_next)
        self.assertEqual((pkt_next.proto, pkt_next.dport), (6, 0))

        # Excessive chain (>8 extension headers) rejected
        chain = b"".join(struct.pack("!BB6s", 60, 0, b"\0" * 6) for _ in range(9)) + tcp
        v6_long = struct.pack("!IHBB", 6 << 28, len(chain), 0, 64) + src6 + dst6
        self.assertIsNone(parse_packet(1.0, eth_hdr + v6_long + chain))


class PcapngTests(unittest.TestCase):
    @staticmethod
    def _ng_block(btype, body, endian="<"):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack(endian + "II", btype, total) + body + (b"\0" * pad) + struct.pack(endian + "I", total)

    @classmethod
    def _ng_shb(cls, endian="<"):
        bom = 0x1A2B3C4D
        body = struct.pack(endian + "IHHq", bom, 1, 0, -1)
        return cls._ng_block(0x0A0D0D0A, body, endian=endian)

    @classmethod
    def _ng_idb(cls, linktype=1, snaplen=65535, endian="<", tsresol=None, tsoffset=None):
        opts = b""
        if tsresol is not None:
            opts += struct.pack(endian + "HHB3x", 9, 1, tsresol)
        if tsoffset is not None:
            opts += struct.pack(endian + "HHq", 14, 8, tsoffset)
        if opts:
            opts += struct.pack(endian + "HH", 0, 0)
        body = struct.pack(endian + "HHI", linktype, 0, snaplen) + opts
        return cls._ng_block(0x00000001, body, endian=endian)

    @classmethod
    def _ng_epb(cls, iface_id, ts_raw, data, orig_len=None, endian="<"):
        orig_len = len(data) if orig_len is None else orig_len
        body = struct.pack(endian + "IIIII", iface_id, ts_raw >> 32, ts_raw & 0xFFFFFFFF, len(data), orig_len) + data
        return cls._ng_block(0x00000006, body, endian=endian)

    @classmethod
    def _ng_spb(cls, data, orig_len=None, endian="<"):
        orig_len = len(data) if orig_len is None else orig_len
        body = struct.pack(endian + "I", orig_len) + data
        return cls._ng_block(0x00000003, body, endian=endian)

    def _temp_path(self, name="capture.pcapng"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return os.path.join(directory.name, name)

    def test_pcapng_le_be_if_tsresol_and_spb(self):
        path = self._temp_path()
        frame1 = synth.tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, SYN)
        frame2 = b"\x00" * 14 + struct.pack("!H", 0x0800) + synth.ipv4("10.0.0.3", "10.0.0.4", 6, b"\0" * 20)
        raw = (
            self._ng_shb("<")
            + self._ng_idb(linktype=1, snaplen=65535, endian="<", tsresol=9)       # 10^-9 s (ns)
            + self._ng_idb(linktype=113, snaplen=65535, endian="<", tsresol=0x82)  # 2^-2 s (0.25s)
            + self._ng_epb(0, 1_700_000_000 * 1_000_000_000 + 250_000_000, frame1, endian="<")
            + self._ng_epb(1, 401, frame2, endian="<")
            + self._ng_spb(b"abcd", orig_len=4, endian="<")
            + self._ng_shb(">")
            + self._ng_idb(linktype=1, snaplen=65535, endian=">", tsoffset=100)
            + self._ng_epb(0, 1_500_000, b"xyz", endian=">")
        )
        Path(path).write_bytes(raw)
        with PcapReader(path) as reader:
            self.assertEqual(reader.linktype, 1)
            records = []
            for ts, data in reader:
                records.append((ts, data, reader.linktype))
        self.assertEqual(len(records), 4)
        self.assertAlmostEqual(records[0][0], 1_700_000_000.25, places=6)
        self.assertEqual((records[0][1], records[0][2]), (frame1, 1))
        self.assertAlmostEqual(records[1][0], 100.25, places=6)
        self.assertEqual((records[1][1], records[1][2]), (frame2, 113))
        self.assertEqual(records[2], (0.0, b"abcd", 1))
        self.assertAlmostEqual(records[3][0], 101.5, places=6)
        self.assertEqual((records[3][1], records[3][2]), (b"xyz", 1))

    def test_pcapng_bounds_checks_raise_pcap_error(self):
        # Unsupported linktype in IDB
        p_bad_lt = self._temp_path("bad_lt.pcapng")
        Path(p_bad_lt).write_bytes(self._ng_shb("<") + self._ng_idb(linktype=999, endian="<"))
        with self.assertRaisesRegex(PcapError, "Unsupported link type 999"):
            PcapReader(p_bad_lt)

        # Block trailing length mismatch
        p_mismatch = self._temp_path("mismatch.pcapng")
        shb = self._ng_shb("<")
        bad_shb = shb[:-4] + struct.pack("<I", 999)
        Path(p_mismatch).write_bytes(bad_shb)
        with self.assertRaisesRegex(PcapError, "block length mismatch"):
            PcapReader(p_mismatch)

        # Unknown interface id in EPB
        p_bad_iface = self._temp_path("bad_iface.pcapng")
        Path(p_bad_iface).write_bytes(
            self._ng_shb("<") + self._ng_idb(1, endian="<") + self._ng_epb(3, 10, b"abc", endian="<")
        )
        with PcapReader(p_bad_iface) as reader:
            with self.assertRaisesRegex(PcapError, "unknown pcapng interface id 3"):
                list(reader)

        # cap_len > orig_len
        p_bad_len = self._temp_path("bad_len.pcapng")
        Path(p_bad_len).write_bytes(
            self._ng_shb("<") + self._ng_idb(1, endian="<")
            + self._ng_epb(0, 10, b"abcdef", orig_len=3, endian="<")
        )
        with PcapReader(p_bad_len) as reader:
            with self.assertRaisesRegex(PcapError, "exceeds original length"):
                list(reader)

        # Packet block before IDB
        p_no_idb = self._temp_path("no_idb.pcapng")
        Path(p_no_idb).write_bytes(self._ng_shb("<") + self._ng_epb(0, 10, b"abc", endian="<"))
        with self.assertRaisesRegex(PcapError, "before interface description"):
            PcapReader(p_no_idb)


if __name__ == "__main__":
    unittest.main()
