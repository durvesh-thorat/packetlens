"""Ties parsing, detectors, time-series bins and live statistics together."""
import threading
from collections import Counter, deque

from .detectors import default_detectors
from .parsers import LINKTYPE_ETHERNET, parse_packet, protocol_name
from .timeseries import BinAggregator, EwmaZScoreDetector


class Engine:
    def __init__(self, packet_detectors=None, bin_detector=None, bin_width=1.0, history=600):
        self.packet_detectors = default_detectors() if packet_detectors is None else packet_detectors
        self.bin_detector = bin_detector or EwmaZScoreDetector()
        self.agg = BinAggregator(bin_width)
        self.alerts = deque(maxlen=500)
        self.bins = deque(maxlen=history)
        self.total_packets = self.total_bytes = self.malformed = 0
        self.last_ts = 0.0
        self.protocols = Counter()
        self.talkers = Counter()
        self._lock = threading.Lock()

    def process(self, ts, data, linktype=LINKTYPE_ETHERNET):
        """Decode one raw frame and feed it. Returns the alerts it caused."""
        pkt = parse_packet(ts, data, linktype)
        if pkt is None:
            with self._lock:
                self.malformed += 1
            return []
        return self.feed(pkt)

    def feed(self, pkt):
        new = []
        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt.length
            self.last_ts = pkt.ts
            self.protocols[protocol_name(pkt)] += 1
            if pkt.src:
                self.talkers[pkt.src] += pkt.length
                if len(self.talkers) > 20000:
                    self.talkers = Counter(dict(self.talkers.most_common(5000)))
            for d in self.packet_detectors:
                new.extend(d.observe(pkt))
            for b in self.agg.add(pkt):
                self._on_bin(b, new)
            self.alerts.extend(new)
        return new

    def _on_bin(self, b, new):
        self.bins.append(b)
        new.extend(self.bin_detector.update(b))

    def finish(self):
        """Flush the last partial bin at the end of a file."""
        new = []
        with self._lock:
            for b in self.agg.flush():
                self._on_bin(b, new)
            self.alerts.extend(new)
        return new

    def snapshot(self, last_bins=120, last_alerts=40):
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "malformed": self.malformed,
                "now": self.last_ts,
                "protocols": dict(self.protocols),
                "talkers": self.talkers.most_common(8),
                "bins": list(self.bins)[-last_bins:],
                "alerts": [a.to_dict() for a in list(self.alerts)[-last_alerts:]][::-1],
            }
