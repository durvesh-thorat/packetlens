"""Classic pcap reader and writer, written from the file-format spec (no libraries).

Layout of a pcap file:
    global header (24 bytes)   magic, version, timezone, sigfigs, snaplen, linktype
    then repeated:
        record header (16 bytes)   ts_sec, ts_frac, captured_len, original_len
        packet bytes (captured_len)
The magic number tells us the byte order AND whether ts_frac is micro- or nanoseconds.
"""
import struct

from .parsers import SUPPORTED_LINKTYPES

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),   # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1e6),   # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),   # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1e9),   # big-endian, nanoseconds
}


class PcapError(ValueError):
    pass


class PcapReader:
    """Iterate over (timestamp_seconds, packet_bytes). `linktype` says how to decode them."""

    def __init__(self, path):
        self._f = open(path, "rb")
        try:
            head = self._f.read(24)
            self._check(head)
            self._endian, self._res = _MAGIC[head[:4]]
            fields = struct.unpack(self._endian + "4sHHiIII", head)
            if fields[1:3] != (2, 4):
                raise PcapError(
                    f"unsupported classic pcap version {fields[1]}.{fields[2]}; "
                    "expected 2.4"
                )
        except PcapError:
            self._f.close()
            raise
        self.snaplen, self.linktype = fields[5], fields[6]
        if self.linktype not in SUPPORTED_LINKTYPES:
            raise PcapError(
                f"Unsupported link type {self.linktype}. Supported: Ethernet (1) and Linux cooked (113)."
            )

    @staticmethod
    def _check(head):
        if len(head) < 24:
            raise PcapError("file is too short to be a pcap file")
        if head[:4] not in _MAGIC:
            raise PcapError("not a classic pcap file (pcapng is not supported; "
                            "convert with: editcap -F pcap in.pcapng out.pcap)")

    def __iter__(self):
        rec = struct.Struct(self._endian + "IIII")
        read = self._f.read
        while True:
            h = read(16)
            if not h:
                return
            if len(h) < 16:
                raise PcapError("truncated pcap record header")
            sec, frac, incl, orig = rec.unpack(h)
            if frac >= self._res:
                raise PcapError(
                    f"pcap timestamp fraction {frac} is outside declared resolution "
                    f"{self._res:g}"
                )
            if incl > orig:
                raise PcapError(
                    f"pcap captured length {incl} exceeds original length {orig}"
                )
            if self.snaplen and incl > self.snaplen:
                raise PcapError(
                    f"pcap captured length {incl} exceeds snaplen {self.snaplen}"
                )
            data = read(incl)
            if len(data) < incl:
                raise PcapError("truncated pcap packet data")
            yield sec + frac / self._res, data

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class PcapWriter:
    """Writes little-endian, microsecond pcap files that Wireshark opens directly."""

    def __init__(self, path, linktype=1, snaplen=65535):
        if linktype not in SUPPORTED_LINKTYPES:
            raise PcapError(
                f"Unsupported link type {linktype}. Supported: Ethernet (1) and Linux cooked (113)."
            )
        self._f = open(path, "wb")
        self.snaplen = snaplen
        self._f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts, data):
        if self.snaplen and len(data) > self.snaplen:
            raise PcapError(
                f"pcap packet length {len(data)} exceeds snaplen {self.snaplen}"
            )
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, 0
        self._f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self._f.write(data)

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
