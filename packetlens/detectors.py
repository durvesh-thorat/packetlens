"""Rule-based and statistical detectors that look at one packet at a time.

Every detector has `observe(packet) -> list[Alert]`. State is bounded (deques with caps,
periodic cleanup) so a flood of attack traffic cannot exhaust memory.
"""
import math
from collections import Counter, deque
from dataclasses import asdict, dataclass

from .parsers import fmt_mac


@dataclass
class Alert:
    ts: float
    kind: str
    severity: str
    src: str
    detail: str

    def to_dict(self):
        return asdict(self)


class SlidingDistinct:
    """Counts distinct keys seen in the last `window` seconds, O(1) amortised per add."""

    __slots__ = ("window", "max_items", "_q", "_counts")

    def __init__(self, window, max_items=4096):
        self.window, self.max_items = window, max_items
        self._q, self._counts = deque(), {}

    def add(self, ts, key):
        q, c = self._q, self._counts
        q.append((ts, key))
        c[key] = c.get(key, 0) + 1
        cutoff = ts - self.window
        while q and (q[0][0] < cutoff or len(q) > self.max_items):
            _, k = q.popleft()
            n = c[k] - 1
            if n:
                c[k] = n
            else:
                del c[k]
        return len(c)


class PortScanDetector:
    """One source probing many different ports on one destination with bare SYNs.

    Two windows catch two styles: a fast scan (many ports in seconds) and a slow scan
    (one port per second, trying to hide under a short window).
    Known blind spot: a scan of ONE port across MANY hosts (horizontal scan) looks like
    a normal client talking to many servers, so it is intentionally not flagged here.
    """

    name = "port_scan"

    def __init__(self, windows=((10, 20), (300, 60)), cooldown=60.0):
        self.windows, self.cooldown = windows, cooldown
        self._state = {}      # (src, dst) -> [SlidingDistinct per window, last_seen, last_alert]
        self._seen = 0

    def observe(self, p):
        if not p.is_syn_only:
            return ()
        self._seen += 1
        if self._seen % 20000 == 0:
            self._cleanup(p.ts)
        key = (p.src, p.dst)
        st = self._state.get(key)
        if st is None:
            st = self._state[key] = [[SlidingDistinct(w) for w, _ in self.windows], p.ts, -1e18]
        st[1] = p.ts
        hit = None
        for sd, (w, thr) in zip(st[0], self.windows):
            n = sd.add(p.ts, p.dport)
            if n >= thr and hit is None:
                hit = (n, w)
        if hit and p.ts - st[2] >= self.cooldown:
            st[2] = p.ts
            return [Alert(p.ts, self.name, "high", p.src,
                          f"{hit[0]} distinct ports probed on {p.dst} within {hit[1]}s")]
        return ()

    def _cleanup(self, now):
        horizon = now - max(w for w, _ in self.windows) - self.cooldown
        for k in [k for k, v in self._state.items() if v[1] < horizon]:
            del self._state[k]


class SynFloodDetector:
    """Too many bare SYN packets reaching ONE service (address + port) within one second.

    Keying on the port is what separates a flood from a fast scan: a scan sends one SYN to
    each of many ports, a flood piles thousands onto the same port.
    """

    name = "syn_flood"

    def __init__(self, threshold=300, cooldown=30.0):
        self.threshold, self.cooldown = threshold, cooldown
        self._b = {}          # (dst, dport) -> [second, count, set(sources)]
        self._last = {}       # (dst, dport) -> last alert ts

    def observe(self, p):
        if not p.is_syn_only:
            return ()
        sec = int(p.ts)
        key = (p.dst, p.dport)
        b = self._b.get(key)
        if b is None or b[0] != sec:
            if len(self._b) > 10000:
                self._b = {k: v for k, v in self._b.items() if v[0] >= sec - 1}
            b = self._b[key] = [sec, 0, set()]
        b[1] += 1
        if len(b[2]) < 1000:
            b[2].add(p.src)
        if b[1] == self.threshold and p.ts - self._last.get(key, -1e18) >= self.cooldown:
            self._last[key] = p.ts
            srcs = len(b[2])
            return [Alert(p.ts, self.name, "high", p.src if srcs == 1 else "many",
                          f">= {self.threshold} SYN packets/s to {p.dst}:{p.dport} from {srcs} source(s)")]
        return ()


_TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "co.in", "org.in", "net.in",
                       "ac.in", "gov.in", "co.jp", "com.br", "co.nz"}


def split_domain(name):
    """('a.b.example.co.uk') -> ('a.b', 'example.co.uk'). Simplified public-suffix handling."""
    parts = name.rstrip(".").split(".")
    k = 3 if ".".join(parts[-2:]) in _TWO_LEVEL_SUFFIXES else 2
    if len(parts) <= k:
        return "", ".".join(parts)
    return ".".join(parts[:-k]), ".".join(parts[-k:])


def shannon_entropy(s):
    """Bits per character. English-like labels ~2.5-3.5, random base32/hex 3.8-4.8."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


class _DomainWindow:
    def __init__(self, span, cap=500):
        self.span, self.cap = span, cap
        self.q, self.counts = deque(), {}
        self.sum_len, self.sum_ent = 0, 0.0

    def add(self, ts, sub):
        ent = shannon_entropy(sub.replace(".", ""))
        self.q.append((ts, sub, len(sub), ent))
        self.counts[sub] = self.counts.get(sub, 0) + 1
        self.sum_len += len(sub)
        self.sum_ent += ent
        cutoff = ts - self.span
        while self.q and (self.q[0][0] < cutoff or len(self.q) > self.cap):
            _, s, ln, en = self.q.popleft()
            self.sum_len -= ln
            self.sum_ent -= en
            n = self.counts[s] - 1
            if n:
                self.counts[s] = n
            else:
                del self.counts[s]
        n = len(self.q)
        return len(self.counts), self.sum_len / n, self.sum_ent / n


class DnsTunnelDetector:
    """Data smuggled inside DNS names: many unique, long, high-entropy subdomains of one domain.

    Known false-positive risk: CDNs and anti-virus cloud lookups also use random-looking
    names. Requiring several signals together (count AND length AND entropy) limits that.
    """

    name = "dns_tunnel"

    def __init__(self, span=60.0, min_unique=10, min_avg_len=20, min_avg_entropy=3.3, cooldown=60.0):
        self.span, self.min_unique = span, min_unique
        self.min_avg_len, self.min_avg_entropy, self.cooldown = min_avg_len, min_avg_entropy, cooldown
        self._w, self._last = {}, {}

    def observe(self, p):
        if p.dns is None or p.dns[2]:               # only queries, not responses
            return ()
        sub, base = split_domain(p.dns[0])
        if not sub:
            return ()
        key = (p.src, base)
        w = self._w.get(key)
        if w is None:
            if len(self._w) > 5000:
                self._w.clear()
            w = self._w[key] = _DomainWindow(self.span)
        uniq, avg_len, avg_ent = w.add(p.ts, sub)
        if (uniq >= self.min_unique and avg_len >= self.min_avg_len and avg_ent >= self.min_avg_entropy
                and p.ts - self._last.get(key, -1e18) >= self.cooldown):
            self._last[key] = p.ts
            return [Alert(p.ts, self.name, "high", p.src,
                          f"{uniq} unique subdomains of {base} in {self.span:.0f}s "
                          f"(avg length {avg_len:.0f}, entropy {avg_ent:.2f} bits/char)")]
        return ()


class ArpSpoofDetector:
    """An IP address suddenly claimed by a different hardware address (man-in-the-middle sign).

    Legitimate causes exist (DHCP renewal, failover, replaced network card), so this is a
    medium-severity signal that needs a human to confirm.
    """

    name = "arp_spoof"

    def __init__(self, cooldown=60.0):
        self.cooldown = cooldown
        self._table, self._last = {}, {}

    def observe(self, p):
        if p.arp is None:
            return ()
        _op, mac, ip = p.arp
        if ip == "0.0.0.0":                         # ARP probe, carries no mapping
            return ()
        old = self._table.get(ip)
        self._table[ip] = mac
        if old is not None and old != mac and p.ts - self._last.get(ip, -1e18) >= self.cooldown:
            self._last[ip] = p.ts
            return [Alert(p.ts, self.name, "medium", fmt_mac(mac),
                          f"{ip} moved from {fmt_mac(old)} to {fmt_mac(mac)}")]
        return ()


def default_detectors():
    return [PortScanDetector(), SynFloodDetector(), DnsTunnelDetector(), ArpSpoofDetector()]
