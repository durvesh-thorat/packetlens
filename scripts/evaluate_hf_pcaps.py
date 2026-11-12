"""Run PacketLens Engine against curated classic PCAPs in `hf_pcaps/`."""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packetlens.engine import Engine
from packetlens.pcap import PcapReader
from packetlens.policy import effective_policy


def analyze_capture(pcap_path: Path, policy, sample_limit=5):
    engine = Engine(policy=policy)
    alerts = []
    first_ts = None
    last_ts = None
    t0 = time.perf_counter()
    with PcapReader(pcap_path) as reader:
        linktype = reader.linktype
        for ts, data in reader:
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            alerts.extend(engine.process(ts, data, linktype))
    alerts.extend(engine.finish())
    elapsed_s = time.perf_counter() - t0
    snap = engine.snapshot()
    duration_s = max(0.0, (last_ts - first_ts)) if first_ts is not None and last_ts is not None else 0.0
    hours = duration_s / 3600.0 if duration_s > 0 else 0.0
    by_kind = Counter(a.kind for a in alerts)
    alerts_per_hour = {k: round(v / hours, 2) if hours > 0 else None for k, v in by_kind.items()}
    return {
        "linktype": linktype,
        "packets": snap["total_packets"],
        "bytes": snap["total_bytes"],
        "malformed": snap["malformed"],
        "duration_s": round(duration_s, 2),
        "elapsed_s": round(elapsed_s, 2),
        "pps": round(snap["total_packets"] / elapsed_s) if elapsed_s > 0 else 0,
        "avg_processing_us": snap.get("avg_processing_us"),
        "max_processing_us": snap.get("max_processing_us"),
        "alerts_total": len(alerts),
        "alerts_by_kind": dict(sorted(by_kind.items())),
        "alerts_per_hour": alerts_per_hour,
        "sample_alerts": [
            {"ts": round(a.ts, 3), "kind": a.kind, "severity": a.severity, "src": a.src, "detail": a.detail}
            for a in alerts[:sample_limit]
        ],
    }


def main():
    p = argparse.ArgumentParser(description="Analyze imported Hugging Face classic PCAPs")
    p.add_argument("--manifest", default="hf_pcaps/manifest.json")
    p.add_argument("--out", help="optional JSON report output path")
    args = p.parse_args()

    manifest_path = Path(args.manifest)
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    base_dir = manifest_path.parent
    policy = effective_policy()

    report = {"policy": policy.name, "captures": []}
    for entry in entries:
        pcap_path = base_dir / entry["local_path"]
        stats = analyze_capture(pcap_path, policy)
        row = {
            "dataset": entry["dataset"],
            "local_path": entry["local_path"],
            "label": entry["label"],
            "kind": entry["kind"],
            "sha256": entry["sha256"],
            **stats,
        }
        report["captures"].append(row)
        print(
            f"{entry['local_path']:48s} pkts={stats['packets']:9d} mal={stats['malformed']:5d} "
            f"dur={stats['duration_s']:7.1f}s pps={stats['pps']:7d} alerts={stats['alerts_by_kind']}",
            flush=True,
        )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote {out_path}", flush=True)


if __name__ == "__main__":
    main()
