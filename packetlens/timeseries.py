"""Turns the packet stream into a per-second time series and flags volume anomalies.

The detector interface for anything that works on bins (statistical baseline today,
a learned model tomorrow): `update(bin_dict) -> list[Alert]`.
A bin looks like {"t": 1700000012.0, "packets": 131, "bytes": 52410, "syn": 9, "dns": 8, "sources": 23}.
"""
import math

from .detectors import Alert

METRICS = ("packets", "bytes", "syn", "dns", "sources")


class BinAggregator:
    def __init__(self, width=1.0, max_gap=30):
        self.width, self.max_gap = width, max_gap
        self._idx = None
        self._last_ts = None
        self.out_of_order = 0
        self._reset()

    def _reset(self):
        self._v = {"packets": 0, "bytes": 0, "syn": 0, "dns": 0}
        self._src = set()

    def _emit(self):
        b = dict(self._v)
        b["sources"] = len(self._src)
        b["t"] = self._idx * self.width
        return b

    def add(self, p):
        """Add a packet. Returns the list of bins that this packet's arrival completed."""
        if self._last_ts is not None and p.ts < self._last_ts:
            self.out_of_order += 1
        else:
            self._last_ts = p.ts
        idx = int(p.ts // self.width)
        out = []
        if self._idx is None:
            self._idx = idx
        elif idx < self._idx:
            return out
        elif idx > self._idx:
            out.append(self._emit())
            gap = idx - self._idx - 1
            if 0 < gap <= self.max_gap:             # silent seconds are real zeros, keep the series regular
                for k in range(1, gap + 1):
                    out.append({"t": (self._idx + k) * self.width, "packets": 0, "bytes": 0,
                                "syn": 0, "dns": 0, "sources": 0})
            self._idx = idx
            self._reset()
        v = self._v
        v["packets"] += 1
        v["bytes"] += p.length
        if p.is_syn_only:
            v["syn"] += 1
        if p.dns is not None and not p.dns[2]:
            v["dns"] += 1
        if p.src and len(self._src) < 5000:
            self._src.add(p.src)
        return out

    def flush(self):
        if self._idx is None:
            return []
        b = self._emit()
        self._idx = None
        self._reset()
        return [b]


class EwmaZScoreDetector:
    """Baseline = exponentially weighted mean and variance. Alert = value far above baseline.

    z = (x - mean) / sigma, flagged when z >= threshold. Details that matter:
      * sigma has a floor (15% of the mean, and at least 1) so a very quiet or very
        regular series cannot produce huge z values from tiny wiggles;
      * anomalous samples are clipped before updating the baseline, so an attack does
        not instantly become "normal", but a real permanent level shift is slowly learned;
      * one alert per anomalous run (re-armed after `rearm` quiet bins), not one per second.
    """

    name = "volumetric"

    def __init__(self, metrics=("packets", "bytes", "syn", "dns"), alpha=0.05, z=6.0, warmup=30, rearm=5):
        self.metrics, self.alpha, self.z, self.warmup, self.rearm = metrics, alpha, z, warmup, rearm
        self._s = {m: {"mean": 0.0, "var": 0.0, "n": 0, "active": False, "quiet": 0} for m in metrics}
        self.frozen = False
        self.last_flags = set()      # metrics that are anomalous in the most recent bin (for evaluation)

    def freeze(self):
        # A sustained anomaly alerts on every bin while the detector is frozen.
        self.frozen = True

    def update(self, b):
        flags, fresh, measurements = set(), [], []
        for m in self.metrics:
            s, x = self._s[m], b[m]
            if s["n"] >= self.warmup:
                sigma = max(math.sqrt(s["var"]), 0.15 * s["mean"], 1.0)
                z = (x - s["mean"]) / sigma
                if z >= self.z:
                    flags.add(m)
                    if not s["active"]:
                        if not self.frozen:
                            s["active"] = True
                        fresh.append(f"{m} {x:.0f}/s vs baseline {s['mean']:.0f} (z={z:.1f})")
                        measurements.append({"metric": m, "observed": x, "baseline": s["mean"],
                                             "z_score": z, "threshold": self.z})
                    if not self.frozen:
                        s["quiet"] = 0
                    x = s["mean"] + 3 * sigma
                else:
                    if not self.frozen:
                        s["quiet"] += 1
                        if s["quiet"] >= self.rearm:
                            s["active"] = False
            if not self.frozen:
                a = max(self.alpha, 1.0 / (s["n"] + 1))   # plain average while warming up
                d = x - s["mean"]
                s["mean"] += a * d
                s["var"] = (1 - a) * (s["var"] + a * d * d)
                s["n"] += 1
        self.last_flags = flags
        if fresh:
            return [Alert(b["t"], self.name, "medium", "-", "; ".join(fresh), "-",
                          data={"metrics": measurements, "window_s": 1, "z_threshold": self.z})]
        return []
