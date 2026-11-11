"""Synthetic labelled traffic: realistic-looking normal behaviour plus scripted attacks.

Why this exists: public attack captures are large and awkward to reproduce, and live
capture on a home network cannot be shared. Here every packet is built byte by byte
(with valid checksums, so Wireshark opens the result without complaints) and every
attack is written down as a labelled event. That gives exact ground truth for
precision/recall and makes every number in the README reproducible from a seed.
"""
import math
import random
import socket
import struct

from .parsers import ACK, FIN, PSH, RST, SYN

GATEWAY = "192.168.1.1"
CLIENTS = [f"192.168.1.{i}" for i in range(10, 60)]
BASE_TS = 1_700_000_000.0
BROADCAST = b"\xff" * 6

DOMAINS = ["www.google.com", "api.github.com", "cdn.jsdelivr.net", "fonts.gstatic.com",
           "www.youtube.com", "i.ytimg.com", "mail.google.com", "files.pythonhosted.org",
           "registry.npmjs.org", "www.wikipedia.org", "static.xx.fbcdn.net", "login.microsoftonline.com",
           "www.reddit.com", "play.google.com", "update.googleapis.com", "web.whatsapp.com"]


# ---------------------------------------------------------------- packet builders
def checksum(b):
    """Internet checksum: one's-complement sum of 16-bit words."""
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def mac_for(ip):
    return b"\x02\x00" + socket.inet_aton(ip)


def eth(src_mac, dst_mac, ethertype, payload):
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ttl=64):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + payload


def _l4_checksum(src, dst, proto, segment):
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, len(segment))
    return checksum(pseudo + segment)


def tcp_frame(src, dst, sport, dport, flags, seq=0, ack=0, payload=b""):
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0)
    seg = hdr + payload
    seg = seg[:16] + struct.pack("!H", _l4_checksum(src, dst, 6, seg)) + seg[18:]
    return eth(mac_for(src), mac_for(dst), 0x0800, ipv4(src, dst, 6, seg))


def udp_frame(src, dst, sport, dport, payload):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = _l4_checksum(src, dst, 17, seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", csum) + seg[8:]
    return eth(mac_for(src), mac_for(dst), 0x0800, ipv4(src, dst, 17, seg))


def encode_name(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"


def dns_frame(src, dst, sport, dport, txid, name, qtype=1, response=False, rng=None):
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    if response:
        head = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([34, 120, 7, 9])
        payload = head + question + answer
    else:
        payload = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    return udp_frame(src, dst, sport, dport, payload)


def arp_frame(op, sender_ip, sender_mac, target_ip, target_mac, dst_mac=BROADCAST):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sender_mac + socket.inet_aton(sender_ip) \
        + target_mac + socket.inet_aton(target_ip)
    return eth(sender_mac, dst_mac, 0x0806, body)


def icmp_echo_frame(src, dst, seq, reply=False):
    msg = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, 1, seq) + b"x" * 32
    msg = msg[:2] + struct.pack("!H", checksum(msg)) + msg[4:]
    return eth(mac_for(src), mac_for(dst), 0x0800, ipv4(src, dst, 1, msg))


# ---------------------------------------------------------------- normal traffic
def _servers(rng, n=40):
    return [f"{rng.choice((34, 52, 104, 142, 151, 172))}.{rng.randrange(256)}.{rng.randrange(256)}."
            f"{rng.randrange(1, 255)}" for _ in range(n)]


def _web_session(rng, t, frames, servers):
    c, s = rng.choice(CLIENTS), rng.choice(servers)
    domain = rng.choice(DOMAINS)
    sp, dp = rng.randrange(32768, 61000), rng.choice((443, 443, 443, 80, 8080))
    dsp, txid = rng.randrange(32768, 61000), rng.randrange(65536)
    frames.append((t, dns_frame(c, GATEWAY, dsp, 53, txid, domain)))
    t += rng.uniform(0.005, 0.04)
    frames.append((t, dns_frame(GATEWAY, c, 53, dsp, txid, domain, response=True)))
    t += rng.uniform(0.001, 0.01)
    rtt = rng.uniform(0.01, 0.08)
    frames.append((t, tcp_frame(c, s, sp, dp, SYN, seq=1000)))
    t += rtt
    frames.append((t, tcp_frame(s, c, dp, sp, SYN | ACK, seq=5000, ack=1001)))
    t += rtt / 2
    frames.append((t, tcp_frame(c, s, sp, dp, ACK, seq=1001, ack=5001)))
    for i in range(rng.randint(2, 25)):
        t += rng.expovariate(1 / (rtt * 1.5))
        if i % 2 == 0:
            frames.append((t, tcp_frame(c, s, sp, dp, PSH | ACK, payload=bytes(rng.randint(80, 500)))))
        else:
            frames.append((t, tcp_frame(s, c, dp, sp, PSH | ACK, payload=bytes(rng.choice((200, 900, 1400, 1400))))))
    t += rtt
    frames.append((t, tcp_frame(c, s, sp, dp, FIN | ACK)))
    frames.append((t + rtt, tcp_frame(s, c, dp, sp, FIN | ACK)))


def _download(rng, t0, frames, seconds=12, pps=250):
    """A big legitimate download: a volume spike that is NOT an attack (a deliberate hard case)."""
    c, s = "192.168.1.25", "151.101.1.69"
    for i in range(int(seconds * pps)):
        t = t0 + i / pps
        frames.append((t, tcp_frame(s, c, 443, 50100, ACK, payload=bytes(1400))))
        if i % 2 == 0:
            frames.append((t + 0.0005, tcp_frame(c, s, 50100, 443, ACK)))


def _background(rng, duration, frames):
    mac_gw = mac_for(GATEWAY)
    t = 0.5
    while t < duration:
        c = rng.choice(CLIENTS)
        frames.append((t, arp_frame(1, c, mac_for(c), GATEWAY, b"\0" * 6)))
        frames.append((t + 0.001, arp_frame(2, GATEWAY, mac_gw, c, mac_for(c), dst_mac=mac_for(c))))
        t += 20
    t, seq = 2.0, 0
    while t < duration:
        c = rng.choice(CLIENTS)
        frames.append((t, icmp_echo_frame(c, GATEWAY, seq)))
        frames.append((t + 0.002, icmp_echo_frame(GATEWAY, c, seq, reply=True)))
        t, seq = t + 5, seq + 1


# ---------------------------------------------------------------- attacks
def _port_scan(rng, t0, frames, attacker, victim, ports, pps):
    for i, port in enumerate(ports):
        t = t0 + i / pps
        sp = rng.randrange(40000, 60000)
        frames.append((t, tcp_frame(attacker, victim, sp, port, SYN)))
        frames.append((t + 0.0005, tcp_frame(victim, attacker, port, sp, RST | ACK)))
    return t0, t0 + len(ports) / pps


def _syn_flood(rng, t0, frames, victim, pps, seconds):
    for i in range(int(pps * seconds)):
        spoofed = f"{rng.randint(11, 223)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        frames.append((t0 + i / pps, tcp_frame(spoofed, victim, rng.randrange(1024, 65535), 80, SYN)))
    return t0, t0 + seconds


def _udp_flood(rng, t0, frames, attacker, victim, pps, seconds):
    for i in range(int(pps * seconds)):
        frames.append((t0 + i / pps, udp_frame(attacker, victim, rng.randrange(1024, 65535), 5000, bytes(512))))
    return t0, t0 + seconds


def _dns_tunnel(rng, t0, frames, client, domain, queries, qps):
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(queries):
        name = "".join(rng.choice(alphabet) for _ in range(30)) + "." + domain
        frames.append((t0 + i / qps, dns_frame(client, GATEWAY, rng.randrange(32768, 61000), 53,
                                              rng.randrange(65536), name, qtype=16)))
    return t0, t0 + queries / qps


def _arp_spoof(t0, frames, attacker, victim, count, every=2.0):
    for i in range(count):
        frames.append((t0 + i * every, arp_frame(2, GATEWAY, mac_for(attacker), victim, mac_for(victim),
                                                 dst_mac=mac_for(victim))))
    return t0, t0 + count * every


def _horizontal_scan(t0, frames, attacker, pps=100, seconds=3):
    """Probe the private /24 service range and record each target's reset reply."""
    host_count = 253
    for i in range(int(pps * seconds)):
        victim = f"192.168.1.{2 + (i % host_count)}"
        sport = 40000 + (i % 20000)
        ts = t0 + i / pps
        frames.append((ts, tcp_frame(attacker, victim, sport, 445, SYN)))
        frames.append((ts + 0.0005, tcp_frame(victim, attacker, 445, sport, RST | ACK)))
    return t0, t0 + seconds


def generate(duration=300, seed=1, attacks=True, sessions_per_second=8.0):
    """Returns (frames, events). frames = sorted [(timestamp, ethernet_frame_bytes)].
    events = ground-truth list; `detects` names the alert kind that should catch each one."""
    if attacks and duration < 280:
        raise ValueError("attacks are scheduled up to t=270 s, so use --duration 280 or more (or --no-attacks)")
    rng = random.Random(seed)
    frames, events = [], []
    servers = _servers(rng)
    t = 0.0
    while t < duration:
        rate = sessions_per_second * (1 + 0.3 * math.sin(2 * math.pi * t / 120))
        t += rng.expovariate(rate)
        _web_session(rng, t, frames, servers)
    _background(rng, duration, frames)
    if duration >= 120:
        _download(rng, duration * 0.15, frames)          # benign hard case, never labelled
    if attacks:
        def add(kind, detects, src, window, volumetric=False):
            events.append({"kind": kind, "detects": detects, "src": src, "volumetric": volumetric,
                           "start": BASE_TS + window[0], "end": BASE_TS + window[1]})
        victim = "192.168.1.20"
        add("port_scan_fast", "port_scan", "192.168.1.200",
            _port_scan(rng, 70, frames, "192.168.1.200", victim, list(range(1, 1001)), 400), True)
        add("port_scan_slow", "port_scan", "192.168.1.201",
            _port_scan(rng, 90, frames, "192.168.1.201", victim, rng.sample(range(1, 1025), 90), 1))
        add("dns_tunnel", "dns_tunnel", "192.168.1.30",
            _dns_tunnel(rng, 120, frames, "192.168.1.30", "t.exfil-example.com", 150, 2.5))
        add("syn_flood", "syn_flood", "many", _syn_flood(rng, 200, frames, victim, 2000, 5), True)
        add("udp_flood", "volumetric", "192.168.1.202",
            _udp_flood(rng, 230, frames, "192.168.1.202", victim, 3000, 8), True)
        add("arp_spoof", "arp_spoof", "02:00:c0:a8:01:c8",
            _arp_spoof(260, frames, "192.168.1.200", victim, 5))
        add("horizontal_scan", "horizontal_scan", "192.168.1.203",
            _horizontal_scan(270, frames, "192.168.1.203"), volumetric=True)
    frames = [(BASE_TS + ts, f) for ts, f in frames]
    frames.sort(key=lambda x: x[0])
    return frames, events
