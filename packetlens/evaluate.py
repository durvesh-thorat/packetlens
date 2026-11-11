"""Reproducible evaluation on labelled synthetic traffic, and a throughput benchmark.

Two kinds of result:
  1. Event level:  was each scripted attack detected, and how many seconds later?
  2. Alert level:  of all alerts raised, how many fall inside an attack window (precision)?
     Alerts on attack-free traffic are false positives, reported per detector.
Plus a bin-level comparison of volume detectors (z-score vs Isolation Forest).
"""
import json
import time
from collections import Counter

from .engine import Engine
from .parsers import parse_packet
from .synth import generate
from .timeseries import BinAggregator, EwmaZScoreDetector

LEAD, SLACK = 2.0, 30.0       # alert may come 2 s before the labelled start or 30 s after the end


def run_engine(frames):
    eng, alerts = Engine(), []
    for ts, data in frames:
        alerts += eng.process(ts, data)
    alerts += eng.finish()
    return eng, alerts


def _in_window(ts, ev):
    return ev["start"] - LEAD <= ts <= ev["end"] + SLACK


def score_events(alerts, events):
    rows = []
    for ev in events:
        hits = [a for a in alerts if a.kind == ev["detects"] and _in_window(a.ts, ev)]
        rows.append({"event": ev["kind"], "detector": ev["detects"], "detected": bool(hits),
                     "delay_s": round(min(a.ts for a in hits) - ev["start"], 1) if hits else None})
    explained = [a for a in alerts if any(_in_window(a.ts, ev) for ev in events)]
    return rows, explained


def bins_of(frames):
    agg, bins = BinAggregator(), []
    for ts, data in frames:
        p = parse_packet(ts, data)
        if p:
            bins += agg.add(p)
    return bins + agg.flush()


def bin_level(attack_bins, events, benign_bins):
    """Volume-detector comparison. Positive bin = overlaps an attack that changes traffic volume."""
    vol = [e for e in events if e["volumetric"]]
    truth = [any(e["start"] - 1 <= b["t"] <= e["end"] for e in vol) for b in attack_bins]
    z = EwmaZScoreDetector()
    zflags = []
    for b in attack_bins:
        z.update(b)
        zflags.append(bool(z.last_flags))
    results = {"zscore_adaptive": _prf(truth, zflags)}
    try:
        from .ml import IsolationForestDetector
        clf = IsolationForestDetector().fit(benign_bins)
        results["isolation_forest"] = _prf(truth, clf.predict(attack_bins))
    except RuntimeError:
        results["isolation_forest"] = None
    return results


def _prf(truth, pred):
    tp = sum(1 for t, p in zip(truth, pred) if t and p)
    fp = sum(1 for t, p in zip(truth, pred) if not t and p)
    fn = sum(1 for t, p in zip(truth, pred) if t and not p)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3)}


def evaluate(duration=300, benign_seed=7, attack_seed=8):
    benign, _ = generate(duration, seed=benign_seed, attacks=False)
    attack, events = generate(duration, seed=attack_seed, attacks=True)
    _, benign_alerts = run_engine(benign)
    _, attack_alerts = run_engine(attack)
    rows, explained = score_events(attack_alerts, events)
    hours = duration / 3600
    out = {
        "duration_s": duration, "packets_benign": len(benign), "packets_attack": len(attack),
        "events": rows,
        "alerts_total": len(attack_alerts), "alerts_in_attack_windows": len(explained),
        "alert_precision": round(len(explained) / len(attack_alerts), 3) if attack_alerts else None,
        "false_positives_on_clean_traffic": dict(Counter(a.kind for a in benign_alerts)),
        "false_positives_per_hour": round(len(benign_alerts) / hours, 1),
        "false_positive_details": [a.detail for a in benign_alerts],
        "bin_level_volume_detectors": bin_level(bins_of(attack), events, bins_of(benign)),
    }
    return out


def print_report(r):
    print(f"\nEvent detection (attack run, {r['packets_attack']:,} packets)")
    print("| attack | detector | detected | delay (s) |\n|---|---|---|---|")
    for e in r["events"]:
        print(f"| {e['event']} | {e['detector']} | {'yes' if e['detected'] else 'NO'} | {e['delay_s']} |")
    detected = sum(e["detected"] for e in r["events"])
    print(f"\nRecall: {detected}/{len(r['events'])} attacks detected")
    print(f"Alert precision: {r['alerts_in_attack_windows']}/{r['alerts_total']} alerts fall inside an attack window")
    print(f"\nClean traffic ({r['packets_benign']:,} packets, no attacks): "
          f"{sum(r['false_positives_on_clean_traffic'].values())} alert(s) = {r['false_positives_per_hour']}/hour")
    for k, v in r["false_positives_on_clean_traffic"].items():
        print(f"  - {k}: {v}")
    for d in r["false_positive_details"]:
        print(f"    {d}")
    print("\nVolume detectors, per-second bins")
    print("| method | precision | recall | F1 |\n|---|---|---|---|")
    for name, m in r["bin_level_volume_detectors"].items():
        if m:
            print(f"| {name} | {m['precision']} | {m['recall']} | {m['f1']} |")
        else:
            print(f"| {name} | (install scikit-learn) | | |")


def benchmark(duration=600, seed=3):
    frames, _ = generate(duration, seed=seed, attacks=False)
    n = len(frames)
    t = time.perf_counter()
    for ts, data in frames:
        parse_packet(ts, data)
    t_parse = time.perf_counter() - t
    eng = Engine()
    t = time.perf_counter()
    for ts, data in frames:
        eng.process(ts, data)
    t_full = time.perf_counter() - t
    return {"packets": n, "parse_only_pps": round(n / t_parse), "full_pipeline_pps": round(n / t_full)}


def save(result, path):
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
