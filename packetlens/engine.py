"""Ties parsing, detectors, time-series bins and live statistics together."""
import threading
import math
from collections import Counter, deque
from os import PathLike

from .detectors import (ArpSpoofDetector, DnsTunnelDetector, HorizontalScanDetector,
                        PortScanDetector, SynFloodDetector, default_detectors)
from .hosts import HostTable
from .parsers import LINKTYPE_ETHERNET, parse_packet, protocol_name
from .policy import Policy, load_policy, rule_matches
from .timeseries import BinAggregator, EwmaZScoreDetector


class Engine:
    def __init__(self, packet_detectors=None, bin_detector=None, bin_width=1.0, history=600,
                 policy=None, store=None):
        self.policy = (load_policy(policy) if isinstance(policy, (str, bytes, PathLike)) else
                       Policy(policy) if isinstance(policy, dict) else policy)
        self.store = store
        self.hosts = HostTable()
        self._pending_bins = deque(maxlen=1000)
        self._next_store_flush = None
        self._packet_bindings = []
        self._volume_bindings = []
        if self.policy is None:
            detectors = default_detectors() if packet_detectors is None else packet_detectors
            self._packet_bindings = [(detector, None) for detector in detectors]
            self.bin_detector = bin_detector or EwmaZScoreDetector()
            self._volume_bindings = [(self.bin_detector, None)]
        else:
            if self.store is not None:
                self.store.incident_gap_s = self.policy.incident_gap_s
            constructors = {
                "port_scan": PortScanDetector, "syn_flood": SynFloodDetector,
                "dns_tunnel": DnsTunnelDetector, "arp_spoof": ArpSpoofDetector,
                "horizontal_scan": HorizontalScanDetector,
            }
            for rule in self.policy.policies:
                if not rule.get("enabled", False):
                    continue
                params = dict(rule.get("params", {}))
                if rule["detector"] == "volumetric":
                    params["metrics"] = tuple(params.get("metrics", ("packets", "bytes", "syn", "dns")))
                    self._volume_bindings.append((EwmaZScoreDetector(**params), rule))
                else:
                    if "windows" in params:
                        params["windows"] = tuple(tuple(window) for window in params["windows"])
                    self._packet_bindings.append(
                        (constructors[rule["detector"]](**params), rule))
            self.packet_detectors = [detector for detector, _ in self._packet_bindings]
            self.bin_detector = self._volume_bindings[0][0] if self._volume_bindings else None
        self.packet_detectors = [detector for detector, _ in self._packet_bindings]
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
        try:
            ts = float(ts)
            if not math.isfinite(ts):
                raise ValueError("timestamp must be finite")
        except (TypeError, ValueError, OverflowError):
            with self._lock:
                self.malformed += 1
            return []
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
            proto = protocol_name(pkt)
            self.protocols[proto] += 1
            if self.store is not None:
                self.hosts.update(pkt, proto)
            if pkt.src:
                self.talkers[pkt.src] += pkt.length
                if len(self.talkers) > 20000:
                    self.talkers = Counter(dict(self.talkers.most_common(5000)))
            for detector, rule in self._packet_bindings:
                observed = detector.observe(pkt)
                new.extend(observed if rule is None else self._apply_policy(observed, rule))
            for b in self.agg.add(pkt):
                self._on_bin(b, new)
            new = self._record_alerts(new)
            self.alerts.extend(new)
            if self.store is not None:
                if self._next_store_flush is None:
                    self._next_store_flush = (int(pkt.ts // 10) + 1) * 10
                elif pkt.ts >= self._next_store_flush:
                    self._flush_store()
                    self._next_store_flush = (int(pkt.ts // 10) + 1) * 10
        return new

    def _on_bin(self, b, new):
        self.bins.append(b)
        if self.store is not None:
            self._pending_bins.append(dict(b))
        for detector, rule in self._volume_bindings:
            new.extend(self._apply_policy(detector.update(b), rule))

    @staticmethod
    def _apply_policy(alerts, rule):
        if rule is None:
            return alerts
        result = []
        for alert in alerts:
            if rule_matches(rule, alert.src, alert.dst):
                continue
            if rule.get("severity"):
                alert.severity = rule["severity"]
            alert.policy_id = rule["id"]
            alert._action = rule.get("action", "alert")
            result.append(alert)
        return result

    def _record_alerts(self, alerts):
        for alert in alerts:
            if self.store is not None:
                self.hosts.record_alert(alert.src, alert.dst)
                self.store.add_alert(alert)
        return alerts

    def _flush_store(self):
        if self.store is None:
            return
        self.store.upsert_hosts(self.hosts.snapshot())
        while self._pending_bins:
            self.store.add_minute_stat(self._pending_bins.popleft())
        self.store.flush()

    def finish(self):
        """Flush the last partial bin at the end of a file."""
        new = []
        with self._lock:
            for b in self.agg.flush():
                self._on_bin(b, new)
            new = self._record_alerts(new)
            self.alerts.extend(new)
            self._flush_store()
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
