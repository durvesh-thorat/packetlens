"""Classic pcap reader and writer, written from the file-format spec (no libraries).

Layout of a pcap file:
    global header (24 bytes)   magic, version, timezone, sigfigs, snaplen, linktype
    then repeated:
        record header (16 bytes)   ts_sec, ts_frac, captured_len, original_len
        packet bytes (captured_len)
The magic number tells us the byte order AND whether ts_frac is micro- or nanoseconds.
"""
import struct

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
        except PcapError:
            self._f.close()
            raise
        self._endian, self._res = _MAGIC[head[:4]]
        fields = struct.unpack(self._endian + "4sHHiIII", head)
        self.snaplen, self.linktype = fields[5], fields[6]

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
            if len(h) < 16:
                return
            sec, frac, incl, _orig = rec.unpack(h)
            data = read(incl)
            if len(data) < incl:      # truncated file: stop cleanly
                return
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
        self._f = open(path, "wb")
        self._f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts, data):
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
