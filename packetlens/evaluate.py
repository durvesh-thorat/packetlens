"""Reproducible evaluation on labelled synthetic traffic, and a throughput benchmark.

Two kinds of result:
  1. Event level:  was each scripted attack detected, and how many seconds later?
  2. Alert level:  of all alerts raised, how many fall inside an attack window (precision)?
     Alerts on attack-free traffic are false positives, reported per detector.
Plus a bin-level comparison of volume detectors (z-score vs Isolation Forest).
"""
import json
import time
from collections import Counter, defaultdict

from .engine import Engine
from .parsers import parse_packet
from .policy import effective_policy
from .stats import block_bootstrap
from .synth import generate
from .timeseries import BinAggregator, EwmaZScoreDetector

LEAD, SLACK = 2.0, 30.0       # alert may come 2 s before the labelled start or 30 s after the end
DEFAULT_BENIGN_SEEDS = (101, 102, 103, 104, 105, 106)
DEFAULT_ATTACK_SEEDS = (201, 202, 203, 204, 205, 206)


def run_engine(frames, policy=None):
    eng, alerts = Engine(policy=policy), []
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


def evaluate_rules(benign_duration=600, attack_duration=300,
                   benign_seeds=DEFAULT_BENIGN_SEEDS, attack_seeds=DEFAULT_ATTACK_SEEDS,
                   policy=None, max_fp_per_hour=1.0):
    """Evaluate every policy rule across held-out synthetic benign and attack seeds."""
    policy = policy or effective_policy()
    benign_counts = Counter()
    clean_bins = defaultdict(list)
    clean_packets = 0
    for seed in benign_seeds:
        frames, _ = generate(benign_duration, seed=seed, attacks=False)
        clean_packets += len(frames)
        _, alerts = run_engine(frames, policy=policy)
        start_ts = frames[0][0] if frames else 0.0
        n_bins = max(1, int(benign_duration // 60))
        seed_hits = defaultdict(set)
        for alert in alerts:
            benign_counts[alert.kind] += 1
            bin_idx = min(n_bins - 1, max(0, int((alert.ts - start_ts) // 60)))
            seed_hits[alert.kind].add(bin_idx)
        for rule in policy.policies:
            det = rule["detector"]
            clean_bins[det].extend((idx in seed_hits[det]) for idx in range(n_bins))

    tp = Counter()
    fn = Counter()
    fp_outside_window = Counter()
    delays = defaultdict(list)
    attack_packets = 0
    for seed in attack_seeds:
        frames, events = generate(attack_duration, seed=seed, attacks=True)
        attack_packets += len(frames)
        _, alerts = run_engine(frames, policy=policy)
        for ev in events:
            det = ev["detects"]
            hits = [a for a in alerts if a.kind == det and _in_window(a.ts, ev)]
            if hits:
                tp[det] += 1
                delays[det].append(min(a.ts for a in hits) - ev["start"])
            else:
                fn[det] += 1
        for alert in alerts:
            if not any(_in_window(alert.ts, ev) for ev in events):
                fp_outside_window[alert.kind] += 1

    clean_hours = (len(benign_seeds) * benign_duration) / 3600.0
    rules_out = []
    for rule in policy.policies:
        det = rule["detector"]
        t = tp[det]
        f_n = fn[det]
        f_pw = fp_outside_window[det]
        clean_fp = benign_counts[det]
        fp_hr = clean_fp / clean_hours if clean_hours else 0.0
        prec = t / (t + f_pw) if (t + f_pw) else (1.0 if t == 0 and f_pw == 0 else 0.0)
        rec = t / (t + f_n) if (t + f_n) else None
        f1 = (2 * prec * rec / (prec + rec)) if (rec is not None and (prec + rec)) else (0.0 if rec is not None else None)
        ds = delays[det]
        ci, ci_note = block_bootstrap(
            [False] * len(clean_bins[det]),
            clean_bins[det],
            block_length=5,
            bin_seconds=60,
        )
        fp_ci = ([round(ci["ci95"]["false_alarms_per_hour"][0], 2),
                  round(ci["ci95"]["false_alarms_per_hour"][1], 2)]
                 if ci else None)
        meets_target = bool(
            rule.get("enabled", False)
            and rec == 1.0
            and f_n == 0
            and fp_hr <= max_fp_per_hour
            and f_pw == 0
        )
        rules_out.append({
            "id": rule["id"],
            "detector": det,
            "enabled": bool(rule.get("enabled", False)),
            "experimental": bool(rule.get("experimental", False)),
            "tp": t,
            "fn": f_n,
            "fp_outside_window": f_pw,
            "precision": round(prec, 3),
            "recall": round(rec, 3) if rec is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "clean_fp_count": clean_fp,
            "clean_fp_per_hour": round(fp_hr, 2),
            "clean_fp_per_hour_ci95": fp_ci,
            "bootstrap_note": ci_note,
            "mean_delay_s": round(sum(ds) / len(ds), 2) if ds else None,
            "max_delay_s": round(max(ds), 2) if ds else None,
            "meets_m0_synthetic_target": meets_target,
        })
    return {
        "policy": policy.name,
        "benign_seeds": list(benign_seeds),
        "attack_seeds": list(attack_seeds),
        "benign_duration_s": benign_duration,
        "attack_duration_s": attack_duration,
        "clean_hours": round(clean_hours, 2),
        "packets_clean": clean_packets,
        "packets_attack": attack_packets,
        "max_fp_per_hour_target": max_fp_per_hour,
        "rules": rules_out,
    }


def print_rule_report(report):
    print(f"\nPer-rule validation ({report['policy']}, {report['clean_hours']}h clean across "
          f"{len(report['benign_seeds'])} seeds, {len(report['attack_seeds'])} attack runs)")
    print("| rule | detector | experimental | TP | FN | outside-win FP | prec | recall | clean FP/hr (95% CI) | delay max (s) | M0 synth target |")
    print("|---|---|---|---:|---:|---:|---:|---:|---|---:|---|")
    for r in report["rules"]:
        ci = f"{r['clean_fp_per_hour']} {r['clean_fp_per_hour_ci95']}" if r["clean_fp_per_hour_ci95"] else f"{r['clean_fp_per_hour']} ({r['bootstrap_note']})"
        status = "PASS" if r["meets_m0_synthetic_target"] else ("EXPERIMENTAL" if r["experimental"] else "FAIL")
        print(f"| {r['id']} | {r['detector']} | {r['experimental']} | {r['tp']} | {r['fn']} | "
              f"{r['fp_outside_window']} | {r['precision']} | {r['recall']} | {ci} | {r['max_delay_s']} | {status} |")


def save(result, path):
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
