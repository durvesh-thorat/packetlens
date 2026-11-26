import argparse
import json
import shlex
import sqlite3
import sys
import time
from collections import deque

from .engine import Engine
from .parsers import SUPPORTED_LINKTYPES
from .pcap import PcapError, PcapReader, PcapWriter
from .policy import effective_policy, load_policy
from .store import Store


def _check_linktype(linktype):
    if linktype not in SUPPORTED_LINKTYPES:
        raise PcapError(f"Unsupported link type {linktype}. Supported: Ethernet (1) and Linux cooked (113).")


def cmd_analyze(a):
    store = Store(a.db) if a.db else None
    try:
        policy = load_policy(a.policy) if a.policy else None
        eng = Engine(policy=policy, store=store)
        keep_all = bool(a.json or store is None)
        alerts = [] if keep_all else deque(maxlen=200)
        alert_count = 0
        t0 = time.perf_counter()
        try:
            with PcapReader(a.file) as r:
                _check_linktype(r.linktype)
                first_ts = last_ts = None
                for ts, data in r:
                    first_ts = ts if first_ts is None else first_ts
                    last_ts = ts
                    batch = eng.process(ts, data, r.linktype)
                    if batch:
                        alert_count += len(batch)
                        alerts.extend(batch)
        except PcapError as exc:
            sys.exit(str(exc))
        batch = eng.finish()
        if batch:
            alert_count += len(batch)
            alerts.extend(batch)
        dt = max(1e-9, time.perf_counter() - t0)
        s = eng.snapshot()
        if store is not None:
            store.record_capture(a.file, s["total_packets"], s["total_bytes"], s["malformed"],
                                first_ts, last_ts, store.counters()["dropped"])
            store.flush()
        if a.json:
            print(json.dumps({"packets": s["total_packets"], "malformed": s["malformed"],
                              "protocols": s["protocols"], "alerts": [x.to_dict() for x in alerts]}, indent=2))
            return
        print(f"{s['total_packets']:,} packets, {s['total_bytes']:,} bytes, {s['malformed']} malformed "
              f"({s['total_packets'] / dt:,.0f} packets/s)")
        print("Protocols:", ", ".join(f"{k} {v}" for k, v in sorted(s['protocols'].items(), key=lambda x: -x[1])))
        print("Top talkers:", ", ".join(f"{ip} ({b:,} B)" for ip, b in s["talkers"][:5]))
        print(f"\n{alert_count} alert(s)")
        if not getattr(a, "quiet", False):
            for x in alerts:
                print(f"  [{x.severity:6}] t={x.ts:.1f}  {x.kind:16} {x.src:20} {x.detail}")
            if alert_count > len(alerts):
                print(f"  ... ({alert_count - len(alerts):,} earlier alerts persisted to {a.db})")
    finally:
        if store is not None:
            store.close()


def cmd_generate(a):
    from .synth import generate
    frames, events = generate(a.duration, a.seed, attacks=not a.no_attacks)
    with PcapWriter(a.out) as w:
        for ts, data in frames:
            w.write(ts, data)
    ev_path = a.out.rsplit(".", 1)[0] + ".events.json"
    with open(ev_path, "w") as f:
        json.dump(events, f, indent=2)
    print(f"wrote {len(frames):,} packets to {a.out} and {len(events)} labelled attacks to {ev_path}")


def cmd_serve(a):
    from .dashboard import replay_packets, serve
    policy = effective_policy(a.policy)
    store = Store(a.db)
    eng = Engine(policy=policy, store=store)
    if a.pcap:
        try:
            with PcapReader(a.pcap) as probe:
                _check_linktype(probe.linktype)
                linktype = probe.linktype
        except PcapError as exc:
            sys.exit(str(exc))

        def packets():
            with PcapReader(a.pcap) as r:
                for ts, data in r:
                    yield ts, data, r.linktype
        source = replay_packets(packets, a.speed, a.loop)
        source_name = f"pcap:{a.pcap}"
    else:
        from .capture import live_packets

        def source(stop_event=None):
            for pkt in live_packets(a.iface, stop_event=stop_event):
                ts, data, *rest = pkt
                pkt_linktype = rest[0] if rest else 1
                _check_linktype(pkt_linktype)
                yield ts, data, pkt_linktype
        source_name = f"interface:{a.iface or 'default'}"
    serve(eng, source, a.host, a.port, store=store, source_name=source_name,
          policy=policy, results_dir=a.results_dir, allow_non_loopback=a.allow_remote)


def cmd_report(a):
    from .report import write_report
    write_report(a.db, a.out, a.title, a.policy)
    print(f"wrote report to {a.out}")


def cmd_live(a):
    from .capture import live_packets
    policy = load_policy(a.policy) if a.policy else None
    store = Store(a.db) if a.db else None
    eng = Engine(policy=policy, store=store)
    print("Capturing... Ctrl-C to stop. Only capture networks you own or are authorised to monitor.")
    first_ts = last_ts = None
    try:
        for pkt in live_packets(a.iface):
            ts, data, *rest = pkt
            linktype = rest[0] if rest else 1
            _check_linktype(linktype)
            first_ts = ts if first_ts is None else first_ts
            last_ts = ts
            for x in eng.process(ts, data, linktype):
                print(f"[{x.severity}] {x.kind} {x.src} {x.detail}")
    except KeyboardInterrupt:
        s = eng.snapshot()
        print(f"\n{s['total_packets']:,} packets seen")
    finally:
        eng.finish()
        if store is not None:
            s = eng.snapshot()
            store.record_capture(f"interface:{a.iface or 'default'}", s["total_packets"],
                                 s["total_bytes"], s["malformed"], first_ts, last_ts,
                                 store.counters()["dropped"])
            store.close()


def cmd_evaluate(a):
    from .evaluate import evaluate, evaluate_rules, print_report, print_rule_report, save
    from .provenance import build_meta
    if a.rules:
        r = evaluate_rules()
        if a.json:
            print(json.dumps(r, indent=2))
        else:
            print_rule_report(r)
        if a.save:
            r["meta"] = build_meta(
                a.command_line,
                seeds={"benign_seeds": r["benign_seeds"], "attack_seeds": r["attack_seeds"]},
            )
            save(r, a.save)
        return
    r = evaluate(a.duration)
    print_report(r)
    if a.save:
        r["meta"] = build_meta(
            a.command_line, seeds={"benign_traffic": 7, "attack_traffic": 8})
        save(r, a.save)


def cmd_flows(a):
    from .evaluate import import_research
    from .provenance import build_meta
    flows = import_research("flows")
    meta = (build_meta(a.command_line, [*a.benign, *a.attack],
                       seeds={"isolation_forest": 0, "bootstrap": 42})
            if a.save else None)
    result = flows.evaluate_flows(a.benign, a.attack, a.freq, a.train_frac, a.min_attack_flows, a.z,
                                  granite=a.granite)
    flows.print_report(result)
    if a.save:
        flows.save_report(result, a.save, a.train_frac, a.freq, meta=meta)


def cmd_flowmodel(a):
    from .evaluate import import_research
    from .provenance import build_meta
    flowmodel = import_research("flowmodel")
    meta = (build_meta(a.command_line, [a.file],
                       seeds={"random_forest": 42, "isolation_forest": 42, "bootstrap": 42})
            if a.save else None)
    flowmodel.run_experiment(a.file, a.train_frac, a.extended, a.diagnose, a.audit_labels, a.save,
                             attack_label=a.attack_label, meta=meta)


def cmd_reproduce(a):
    from .reproduce import reproduce
    return reproduce(a.data_dir, skip_real=a.skip_real, write=a.write,
                     command_line=a.command_line)


def cmd_render_results(a):
    from .render_results import render_results
    write_docs = True if getattr(a, "write_docs", False) else None
    markdown_path, readme_path = render_results(write_docs=write_docs)
    if markdown_path is not None:
        print(f"wrote {markdown_path}")
    print(f"updated {readme_path}")


def cmd_bench(a):
    from .evaluate import benchmark
    print(json.dumps(benchmark(a.duration), indent=2))


def cmd_policy_validate(a):
    policy = load_policy(a.path)
    print(f"valid: {policy.name}")


def cmd_policy_show(a):
    policy = effective_policy(a.path)
    print(json.dumps(policy.to_dict(), indent=2))


def cmd_incidents(a):
    store = Store(a.db)
    try:
        if a.action == "list":
            result = store.list_incidents(status=a.status, severity=a.severity, kind=a.kind, q=a.q,
                                          limit=a.limit, offset=a.offset)
        elif a.action == "show":
            result = store.get_incident(a.id)
            if result is None:
                raise ValueError(f"incident not found: {a.id}")
        elif a.action == "ack":
            result = store.set_incident_status(a.id, "acknowledged", a.note)
        else:
            result = store.set_incident_status(a.id, "closed", a.note)
        print(json.dumps(result, indent=2))
    finally:
        store.close()


def cmd_store(a):
    store = Store(a.db)
    try:
        if a.store_action == "backup":
            dest = store.backup(a.out)
            print(json.dumps({"backup": dest, "counters": store.counters()}, indent=2))
        else:
            if a.days <= 0:
                raise ValueError("retention days must be positive")
            cutoff = time.time() - a.days * 86400.0
            counts = store.prune_older_than(cutoff)
            print(json.dumps({"cutoff_ts": cutoff, "days": a.days, "deleted": counts}, indent=2))
    finally:
        store.close()


def main(argv=None):
    p = argparse.ArgumentParser(prog="packetlens", description="Network traffic analyzer built from scratch")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("analyze", help="analyse a pcap file and print alerts")
    s.add_argument("file")
    s.add_argument("--json", action="store_true")
    s.add_argument("--quiet", "-q", action="store_true", help="suppress individual alert lines")
    s.add_argument("--policy")
    s.add_argument("--db")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("generate", help="write a synthetic labelled pcap file")
    s.add_argument("out")
    s.add_argument("--duration", type=int, default=300)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--no-attacks", action="store_true")
    s.set_defaults(fn=cmd_generate)

    s = sub.add_parser("serve", help="live dashboard from a pcap replay or a live interface")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap")
    g.add_argument("--iface")
    s.add_argument("--speed", type=float, default=1.0)
    s.add_argument("--loop", action="store_true")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--allow-remote", action="store_true",
                   help="allow binding without TLS to a non-loopback host (unsafe on untrusted networks)")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--policy")
    s.add_argument("--db", default="packetlens.db")
    s.add_argument("--results-dir", default="results")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("report", help="write a self-contained HTML report from a SQLite store")
    s.add_argument("--db", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--title", default="PacketLens Technical Report")
    s.add_argument("--policy", help="policy JSON to include (default: packaged policy)")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("live", help="capture from an interface and print alerts (Linux, root)")
    s.add_argument("--iface")
    s.add_argument("--policy")
    s.add_argument("--db")
    s.set_defaults(fn=cmd_live)

    s = sub.add_parser("evaluate", help="precision/recall on labelled synthetic traffic")
    s.add_argument("--duration", type=int, default=300)
    s.add_argument("--rules", action="store_true",
                   help="run held-out multi-seed per-rule evaluation against M0 targets")
    s.add_argument("--json", action="store_true", help="print JSON output (with --rules)")
    s.add_argument("--save", help="write results as JSON")
    s.set_defaults(fn=cmd_evaluate)

    s = sub.add_parser("flows", help="real-data experiment on CIC-IDS2017 flow files (needs pandas)")
    s.add_argument("--benign", nargs="+", required=True, help="clean day, e.g. the Monday file")
    s.add_argument("--attack", nargs="+", required=True, help="attack-day file(s), e.g. the Friday files")
    s.add_argument("--freq", default="1min")
    s.add_argument("--train-frac", type=float, default=0.6)
    s.add_argument("--min-attack-flows", type=int, default=5)
    s.add_argument("--z", type=float, default=6.0)
    s.add_argument("--granite", action="store_true", help="add zero-shot Granite forecasts (requires the granite extra)")
    s.add_argument("--save", help="write the printed results and run metadata as JSON")
    s.set_defaults(fn=cmd_flows)

    s = sub.add_parser("flowmodel", help="per-flow attack classifier on CIC-IDS2017 (needs pandas and scikit-learn)")
    s.add_argument("--file", default="cicids2017_traffic_label/Friday-WorkingHours-Morning.pcap_ISCX.csv")
    s.add_argument("--attack-label", default="Bot", help="attack label to compare with BENIGN (default: Bot)")
    s.add_argument("--train-frac", type=float, default=0.6)
    s.add_argument("--extended", action="store_true", help="run threshold, machine, duplicate, and feature-ablation experiments")
    s.add_argument("--diagnose", action="store_true", help="run source-IP leakage diagnostic experiments")
    s.add_argument("--audit-labels", action="store_true",
                   help="print Bot label counts against documented Friday attack windows")
    s.add_argument("--save", help="write the printed results and run metadata as JSON")
    s.set_defaults(fn=cmd_flowmodel)

    s = sub.add_parser("reproduce", help="run published experiments and compare result JSON files")
    s.add_argument("--skip-real", action="store_true", help="run only synthetic evaluation and benchmark")
    s.add_argument("--data-dir", default="cicids2017_traffic_label",
                   help="directory containing CIC-IDS2017 flow CSV files")
    s.add_argument("--write", action="store_true", help="overwrite result JSON files (default: dry run)")
    s.set_defaults(fn=cmd_reproduce)

    s = sub.add_parser("render-results", help="generate docs/RESULTS.md and the README results block")
    s.add_argument("--write-docs", action="store_true", help="write docs/RESULTS.md even if docs/ is absent")
    s.set_defaults(fn=cmd_render_results)

    s = sub.add_parser("bench", help="throughput in packets per second")
    s.add_argument("--duration", type=int, default=600)
    s.set_defaults(fn=cmd_bench)

    s = sub.add_parser("policy", help="validate or display detection policies")
    policy_sub = s.add_subparsers(dest="policy_cmd", required=True)
    v = policy_sub.add_parser("validate", help="validate a policy JSON file")
    v.add_argument("path")
    v.set_defaults(fn=cmd_policy_validate)
    v = policy_sub.add_parser("show", help="show an explicit or packaged policy")
    v.add_argument("path", nargs="?")
    v.set_defaults(fn=cmd_policy_show)

    s = sub.add_parser("incidents", help="list or update persisted incidents")
    incident_sub = s.add_subparsers(dest="action", required=True)
    v = incident_sub.add_parser("list")
    v.add_argument("--db", required=True)
    v.add_argument("--status")
    v.add_argument("--severity")
    v.add_argument("--kind")
    v.add_argument("--q")
    v.add_argument("--limit", type=int, default=50)
    v.add_argument("--offset", type=int, default=0)
    v.set_defaults(fn=cmd_incidents)
    for action in ("show", "ack", "close"):
        v = incident_sub.add_parser(action)
        v.add_argument("--db", required=True)
        v.add_argument("id")
        if action in {"ack", "close"}:
            v.add_argument("--note", default="")
        v.set_defaults(fn=cmd_incidents)

    s = sub.add_parser("store", help="backup or prune the SQLite store")
    store_sub = s.add_subparsers(dest="store_action", required=True)
    v = store_sub.add_parser("backup", help="create a WAL-safe backup of a PacketLens SQLite store")
    v.add_argument("--db", required=True)
    v.add_argument("--out", required=True)
    v.set_defaults(fn=cmd_store)
    v = store_sub.add_parser("prune", help="remove closed/expired records older than --days")
    v.add_argument("--db", required=True)
    v.add_argument("--days", type=float, default=30.0)
    v.set_defaults(fn=cmd_store)

    command_args = list(sys.argv[1:] if argv is None else argv)
    a = p.parse_args(command_args)
    a.command_line = shlex.join(["python", "-m", "packetlens", *command_args])
    try:
        a.fn(a)
    except (PcapError, ValueError, RuntimeError, FileNotFoundError, PermissionError, sqlite3.Error) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
