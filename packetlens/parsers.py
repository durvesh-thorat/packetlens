"""Byte-level packet decoding: Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP and the DNS question.

Everything is decoded with `struct` so each field maps to a documented byte offset.
Network byte order is big-endian, hence the "!" in every format string.
"""
import socket
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
ETH_IPV4, ETH_ARP, ETH_VLAN, ETH_IPV6 = 0x0800, 0x0806, 0x8100, 0x86DD
PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMPV6 = 1, 6, 17, 58
LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL = 1, 113
SUPPORTED_LINKTYPES = (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL)


class Malformed(Exception):
    """Raised internally when a packet is too short or inconsistent to decode."""


@dataclass(slots=True)
class Packet:
    ts: float
    length: int
    ethertype: int = 0
    eth_src: bytes = b""
    eth_dst: bytes = b""
    src: str = ""
    dst: str = ""
    proto: int = 0
    ttl: int = 0
    sport: int = 0
    dport: int = 0
    flags: int = 0
    payload_len: int = 0
    icmp_type: int = -1
    dns: Optional[Tuple[str, int, bool]] = None    # (query name, query type, is_response)
    arp: Optional[Tuple[int, bytes, str]] = None   # (opcode, sender MAC, sender IP)

    @property
    def is_syn_only(self) -> bool:
        """A connection attempt: SYN set, ACK not set."""
        return self.proto == PROTO_TCP and (self.flags & (SYN | ACK)) == SYN


def fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def protocol_name(p: Packet) -> str:
    if p.dns is not None:
        return "DNS"
    if p.proto == PROTO_TCP:
        return "TCP"
    if p.proto == PROTO_UDP:
        return "UDP"
    if p.proto in (PROTO_ICMP, PROTO_ICMPV6):
        return "ICMP"
    if p.ethertype == ETH_ARP:
        return "ARP"
    return "Other"


def parse_packet(ts: float, data: bytes, linktype: int = LINKTYPE_ETHERNET) -> Optional[Packet]:
    """Decode one captured frame. Returns None if it is malformed or unsupported."""
    try:
        return _parse(ts, data, linktype)
    except (struct.error, IndexError, OSError, TypeError, ValueError, Malformed):
        return None


def _parse(ts, data, linktype):
    pkt = Packet(ts, len(data))
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            raise Malformed
        pkt.eth_dst, pkt.eth_src = data[0:6], data[6:12]
        (etype,) = struct.unpack_from("!H", data, 12)
        off = 14
        if etype == ETH_VLAN:                       # 802.1Q tag adds 4 bytes
            (etype,) = struct.unpack_from("!H", data, 16)
            off = 18
    elif linktype == LINKTYPE_LINUX_SLL:            # "cooked" capture from `tcpdump -i any`
        if len(data) < 16:
            raise Malformed
        (etype,) = struct.unpack_from("!H", data, 14)
        off = 16
    else:
        return None
    pkt.ethertype = etype
    if etype == ETH_IPV4:
        _parse_ipv4(pkt, data, off)
    elif etype == ETH_IPV6:
        _parse_ipv6(pkt, data, off)
    elif etype == ETH_ARP:
        _parse_arp(pkt, data, off)
    return pkt


def _parse_ipv4(pkt, data, off):
    if len(data) < off + 20:
        raise Malformed
    vihl = data[off]
    ihl = (vihl & 0x0F) * 4                          # header length is in 4-byte words
    if vihl >> 4 != 4 or ihl < 20:
        raise Malformed
    (total_len,) = struct.unpack_from("!H", data, off + 2)
    (frag,) = struct.unpack_from("!H", data, off + 6)
    pkt.ttl = data[off + 8]
    pkt.proto = data[off + 9]
    pkt.src = socket.inet_ntoa(data[off + 12:off + 16])
    pkt.dst = socket.inet_ntoa(data[off + 16:off + 20])
    # total_len lets us ignore Ethernet padding bytes added after the IP packet
    end = min(off + total_len, len(data)) if total_len >= ihl else len(data)
    if frag & 0x1FFF:                                # non-first fragment: no transport header
        return
    _parse_transport(pkt, data, off + ihl, end)


def _parse_ipv6(pkt, data, off):
    if len(data) < off + 40:
        raise Malformed
    payload_len, nxt, hop = struct.unpack_from("!HBB", data, off + 4)
    pkt.ttl, pkt.proto = hop, nxt
    pkt.src = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
    pkt.dst = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
    if nxt in (PROTO_TCP, PROTO_UDP, PROTO_ICMPV6):  # extension headers are not followed
        _parse_transport(pkt, data, off + 40, min(off + 40 + payload_len, len(data)))


def _parse_transport(pkt, data, off, end):
    p = pkt.proto
    if p == PROTO_TCP:
        if end - off < 20:
            raise Malformed
        sport, dport, _seq, _ack, off_flags = struct.unpack_from("!HHIIH", data, off)
        pkt.sport, pkt.dport = sport, dport
        pkt.flags = off_flags & 0xFF                 # CWR ECE URG ACK PSH RST SYN FIN
        pkt.payload_len = max(0, end - off - (off_flags >> 12) * 4)
    elif p == PROTO_UDP:
        if end - off < 8:
            raise Malformed
        sport, dport, _ulen = struct.unpack_from("!HHH", data, off)
        pkt.sport, pkt.dport = sport, dport
        pkt.payload_len = max(0, end - off - 8)
        if sport == 53 or dport == 53:
            pkt.dns = parse_dns(data[off + 8:end])
    elif p in (PROTO_ICMP, PROTO_ICMPV6):
        pkt.icmp_type = data[off]


def _parse_arp(pkt, data, off):
    _htype, _ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, off)
    if hlen != 6 or plen != 4:
        return
    pkt.arp = (op, data[off + 8:off + 14], socket.inet_ntoa(data[off + 14:off + 18]))


def parse_dns(b: bytes):
    """Decode the first DNS question. Returns (name, qtype, is_response) or None."""
    try:
        if len(b) < 12:
            return None
        _txid, flags, qdcount = struct.unpack_from("!HHH", b, 0)
        if qdcount < 1:
            return None
        labels, pos = [], 12
        while True:
            n = b[pos]
            if n == 0:
                pos += 1
                break
            if n & 0xC0:                             # compression pointers do not occur in questions
                return None
            labels.append(b[pos + 1:pos + 1 + n].decode("ascii", "replace"))
            pos += 1 + n
        (qtype,) = struct.unpack_from("!H", b, pos)
        return ".".join(labels).lower(), qtype, bool(flags & 0x8000)
    except (struct.error, IndexError):
        return None
