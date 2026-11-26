"""Classic pcap and basic pcapng reader, plus classic pcap writer (no external libraries).

Layout of a classic pcap file:
    global header (24 bytes)   magic, version, timezone, sigfigs, snaplen, linktype
    then repeated:
        record header (16 bytes)   ts_sec, ts_frac, captured_len, original_len
        packet bytes (captured_len)
The magic number tells us the byte order AND whether ts_frac is micro- or nanoseconds.

Basic pcapng support handles Section Header Blocks (0x0A0D0D0A), Interface Description
Blocks (0x00000001, including if_tsresol and if_tsoffset), Enhanced Packet Blocks
(0x00000006), and Simple Packet Blocks (0x00000003) in both byte orders.
"""
import struct

from .parsers import SUPPORTED_LINKTYPES

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),   # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1e6),   # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),   # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1e9),   # big-endian, nanoseconds
}

_NG_SHB = 0x0A0D0D0A
_NG_SHB_BYTES = b"\x0a\x0d\x0d\x0a"
_NG_IDB = 0x00000001
_NG_SPB = 0x00000003
_NG_EPB = 0x00000006
_NG_BOM_LE = b"\x4d\x3c\x2b\x1a"
_NG_BOM_BE = b"\x1a\x2b\x3c\x4d"
_MAX_NG_BLOCK_LEN = 64 * 1024 * 1024


class PcapError(ValueError):
    pass


def _check_linktype(linktype):
    if linktype not in SUPPORTED_LINKTYPES:
        raise PcapError(
            f"Unsupported link type {linktype}. Supported: Ethernet (1) and Linux cooked (113)."
        )


def _parse_ng_options(raw, endian):
    opts = []
    pos = 0
    end = len(raw)
    while pos < end:
        if pos + 4 > end:
            raise PcapError("truncated pcapng option header")
        code, length = struct.unpack_from(endian + "HH", raw, pos)
        pos += 4
        if code == 0:
            if length != 0:
                raise PcapError("invalid pcapng end-of-options length")
            break
        padded = (length + 3) & ~3
        if pos + padded > end:
            raise PcapError("truncated pcapng option value")
        opts.append((code, raw[pos:pos + length]))
        pos += padded
    return opts


def _parse_ng_shb(head, read_fn):
    bom = head[8:12]
    if bom == _NG_BOM_LE:
        endian = "<"
    elif bom == _NG_BOM_BE:
        endian = ">"
    else:
        raise PcapError("invalid pcapng byte-order magic")
    (total_len,) = struct.unpack(endian + "I", head[4:8])
    if total_len < 28 or total_len % 4 != 0 or total_len > _MAX_NG_BLOCK_LEN:
        raise PcapError(f"invalid pcapng section header block length {total_len}")
    rest = read_fn(total_len - 24)
    if len(rest) < total_len - 24:
        raise PcapError("truncated pcapng section header block")
    block = head + rest
    (trail_len,) = struct.unpack(endian + "I", block[-4:])
    if trail_len != total_len:
        raise PcapError("pcapng block length mismatch")
    major, minor, _section_len = struct.unpack(endian + "HHq", block[12:24])
    if major != 1:
        raise PcapError(f"unsupported pcapng version {major}.{minor}; expected 1.x")
    _parse_ng_options(block[24:-4], endian)
    return endian


def _read_ng_block(read_fn, endian):
    hdr = read_fn(8)
    if not hdr:
        return None
    if len(hdr) < 8:
        raise PcapError("truncated pcapng block header")
    if hdr[:4] == _NG_SHB_BYTES:
        mid = read_fn(16)
        if len(mid) < 16:
            raise PcapError("truncated pcapng section header block")
        return _NG_SHB, _parse_ng_shb(hdr + mid, read_fn), b""
    block_type, total_len = struct.unpack(endian + "II", hdr)
    if total_len < 12 or total_len % 4 != 0 or total_len > _MAX_NG_BLOCK_LEN:
        raise PcapError(f"invalid pcapng block length {total_len}")
    rest = read_fn(total_len - 8)
    if len(rest) < total_len - 8:
        raise PcapError("truncated pcapng block")
    (trail_len,) = struct.unpack(endian + "I", rest[-4:])
    if trail_len != total_len:
        raise PcapError("pcapng block length mismatch")
    return block_type, endian, rest[:-4]


def _parse_ng_idb(body, endian):
    if len(body) < 8:
        raise PcapError("truncated pcapng interface description block")
    linktype, _reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
    ts_units = 1_000_000
    ts_offset = 0
    for code, val in _parse_ng_options(body[8:], endian):
        if code == 9:
            if len(val) != 1:
                raise PcapError("invalid pcapng if_tsresol option length")
            b = val[0]
            if b & 0x80:
                exp = b & 0x7F
                if exp > 63:
                    raise PcapError(f"unsupported pcapng timestamp resolution 2^-{exp}")
                ts_units = 1 << exp
            else:
                if b > 18:
                    raise PcapError(f"unsupported pcapng timestamp resolution 10^-{b}")
                ts_units = 10 ** b
        elif code == 14:
            if len(val) != 8:
                raise PcapError("invalid pcapng if_tsoffset option length")
            (ts_offset,) = struct.unpack(endian + "q", val)
    return {
        "linktype": linktype,
        "snaplen": snaplen,
        "ts_units": ts_units,
        "ts_offset": ts_offset,
    }


def _parse_ng_epb(body, endian, interfaces):
    if len(body) < 20:
        raise PcapError("truncated pcapng enhanced packet block")
    iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(endian + "IIIII", body, 0)
    if iface_id >= len(interfaces):
        raise PcapError(f"unknown pcapng interface id {iface_id}")
    iface = interfaces[iface_id]
    _check_linktype(iface["linktype"])
    if cap_len > orig_len:
        raise PcapError(f"pcap captured length {cap_len} exceeds original length {orig_len}")
    snaplen = iface["snaplen"]
    if snaplen and cap_len > snaplen:
        raise PcapError(f"pcap captured length {cap_len} exceeds snaplen {snaplen}")
    padded = (cap_len + 3) & ~3
    if 20 + padded > len(body):
        raise PcapError("truncated pcapng packet data")
    if 20 + padded < len(body):
        _parse_ng_options(body[20 + padded:], endian)
    ts_raw = (ts_high << 32) | ts_low
    sec, rem = divmod(ts_raw, iface["ts_units"])
    ts = iface["ts_offset"] + sec + rem / iface["ts_units"]
    return ts, body[20:20 + cap_len], iface


def _parse_ng_spb(body, endian, interfaces):
    if len(body) < 4:
        raise PcapError("truncated pcapng simple packet block")
    if not interfaces:
        raise PcapError("pcapng simple packet block before interface description")
    iface = interfaces[0]
    _check_linktype(iface["linktype"])
    (orig_len,) = struct.unpack_from(endian + "I", body, 0)
    snaplen = iface["snaplen"]
    cap_len = min(orig_len, snaplen) if snaplen else orig_len
    padded = (cap_len + 3) & ~3
    if 4 + padded > len(body):
        raise PcapError("truncated pcapng packet data")
    return 0.0, body[4:4 + cap_len], iface


class PcapReader:
    """Iterate over (timestamp_seconds, packet_bytes). `linktype` says how to decode them."""

    def __init__(self, path):
        self._f = open(path, "rb")
        self._format = "pcap"
        self._ng_endian = "<"
        self._ng_interfaces = []
        try:
            head = self._f.read(24)
            if len(head) < 24:
                raise PcapError("file is too short to be a pcap file")
            if head[:4] in _MAGIC:
                self._endian, self._res = _MAGIC[head[:4]]
                fields = struct.unpack(self._endian + "4sHHiIII", head)
                if fields[1:3] != (2, 4):
                    raise PcapError(
                        f"unsupported classic pcap version {fields[1]}.{fields[2]}; "
                        "expected 2.4"
                    )
                self.snaplen, self.linktype = fields[5], fields[6]
                _check_linktype(self.linktype)
            elif head[:4] == _NG_SHB_BYTES:
                self._format = "pcapng"
                self._ng_endian = _parse_ng_shb(head, self._f.read)
                self.snaplen = 0
                self.linktype = SUPPORTED_LINKTYPES[0]
                while True:
                    block = _read_ng_block(self._f.read, self._ng_endian)
                    if block is None:
                        break
                    btype, new_endian, body = block
                    if btype == _NG_SHB:
                        self._ng_endian = new_endian
                        self._ng_interfaces = []
                    elif btype == _NG_IDB:
                        iface = _parse_ng_idb(body, self._ng_endian)
                        _check_linktype(iface["linktype"])
                        self._ng_interfaces.append(iface)
                        self.snaplen = iface["snaplen"]
                        self.linktype = iface["linktype"]
                        break
                    elif btype in (_NG_EPB, _NG_SPB):
                        raise PcapError("pcapng packet block before interface description")
            else:
                raise PcapError("not a classic pcap or pcapng file")
        except PcapError:
            self._f.close()
            raise

    def __iter__(self):
        if self._format == "pcapng":
            yield from self._iter_pcapng()
            return
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

    def _iter_pcapng(self):
        read = self._f.read
        while True:
            block = _read_ng_block(read, self._ng_endian)
            if block is None:
                return
            btype, new_endian, body = block
            if btype == _NG_SHB:
                self._ng_endian = new_endian
                self._ng_interfaces = []
            elif btype == _NG_IDB:
                iface = _parse_ng_idb(body, self._ng_endian)
                _check_linktype(iface["linktype"])
                self._ng_interfaces.append(iface)
            elif btype == _NG_EPB:
                ts, data, iface = _parse_ng_epb(body, self._ng_endian, self._ng_interfaces)
                self.linktype = iface["linktype"]
                self.snaplen = iface["snaplen"]
                yield ts, data
            elif btype == _NG_SPB:
                ts, data, iface = _parse_ng_spb(body, self._ng_endian, self._ng_interfaces)
                self.linktype = iface["linktype"]
                self.snaplen = iface["snaplen"]
                yield ts, data

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class PcapWriter:
    """Writes little-endian, microsecond pcap files that Wireshark opens directly."""

    def __init__(self, path, linktype=1, snaplen=65535):
        _check_linktype(linktype)
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
