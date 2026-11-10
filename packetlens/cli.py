import argparse
import json
import sys
import time

from .engine import Engine
from .parsers import SUPPORTED_LINKTYPES
from .pcap import PcapError, PcapReader, PcapWriter


def _check_linktype(linktype):
    if linktype not in SUPPORTED_LINKTYPES:
        sys.exit(f"Unsupported link type {linktype}. Supported: Ethernet (1) and Linux cooked (113).")


def cmd_analyze(a):
    eng, alerts = Engine(), []
    t0 = time.perf_counter()
    with PcapReader(a.file) as r:
        _check_linktype(r.linktype)
        for ts, data in r:
            alerts += eng.process(ts, data, r.linktype)
    alerts += eng.finish()
    dt = time.perf_counter() - t0
    s = eng.snapshot()
    if a.json:
        print(json.dumps({"packets": s["total_packets"], "malformed": s["malformed"],
                          "protocols": s["protocols"], "alerts": [x.to_dict() for x in alerts]}, indent=2))
        return
    print(f"{s['total_packets']:,} packets, {s['total_bytes']:,} bytes, {s['malformed']} malformed "
          f"({s['total_packets'] / dt:,.0f} packets/s)")
    print("Protocols:", ", ".join(f"{k} {v}" for k, v in sorted(s['protocols'].items(), key=lambda x: -x[1])))
    print("Top talkers:", ", ".join(f"{ip} ({b:,} B)" for ip, b in s["talkers"][:5]))
    print(f"\n{len(alerts)} alert(s)")
    for x in alerts:
        print(f"  [{x.severity:6}] t={x.ts:.1f}  {x.kind:10} {x.src:20} {x.detail}")


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
    from .dashboard import replay, serve
    eng = Engine()
    if a.pcap:
        with PcapReader(a.pcap) as probe:
            _check_linktype(probe.linktype)
            linktype = probe.linktype

        def packets():
            with PcapReader(a.pcap) as r:
                yield from r
        source = replay(eng, packets, linktype, a.speed, a.loop)
    else:
        from .capture import live_packets

        def source():
            for ts, data in live_packets(a.iface):
                eng.process(ts, data, 1)
    serve(eng, source, a.host, a.port)


def cmd_live(a):
    from .capture import live_packets
    eng = Engine()
    print("Capturing... Ctrl-C to stop. Only capture networks you own or are authorised to monitor.")
    try:
        for ts, data in live_packets(a.iface):
            for x in eng.process(ts, data, 1):
                print(f"[{x.severity}] {x.kind} {x.src} {x.detail}")
    except KeyboardInterrupt:
        s = eng.snapshot()
        print(f"\n{s['total_packets']:,} packets seen")


def cmd_evaluate(a):
    from .evaluate import evaluate, print_report, save
    r = evaluate(a.duration)
    print_report(r)
    if a.save:
        save(r, a.save)


def cmd_flows(a):
    from .flows import evaluate_flows, print_report, save_report
    result = evaluate_flows(a.benign, a.attack, a.freq, a.train_frac, a.min_attack_flows, a.z)
    print_report(result)
    if a.save:
        save_report(result, a.save, a.train_frac, a.freq)


def cmd_flowmodel(a):
    from .flowmodel import run_experiment
    run_experiment(a.file, a.train_frac, a.extended, a.diagnose, a.audit_labels, a.save)


def cmd_bench(a):
    from .evaluate import benchmark
    print(json.dumps(benchmark(a.duration), indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(prog="packetlens", description="Network traffic analyzer built from scratch")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("analyze", help="analyse a pcap file and print alerts")
    s.add_argument("file")
    s.add_argument("--json", action="store_true")
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
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("live", help="capture from an interface and print alerts (Linux, root)")
    s.add_argument("--iface")
    s.set_defaults(fn=cmd_live)

    s = sub.add_parser("evaluate", help="precision/recall on labelled synthetic traffic")
    s.add_argument("--duration", type=int, default=300)
    s.add_argument("--save", help="write results as JSON")
    s.set_defaults(fn=cmd_evaluate)

    s = sub.add_parser("flows", help="real-data experiment on CIC-IDS2017 flow files (needs pandas)")
    s.add_argument("--benign", nargs="+", required=True, help="clean day, e.g. the Monday file")
    s.add_argument("--attack", nargs="+", required=True, help="attack-day file(s), e.g. the Friday files")
    s.add_argument("--freq", default="1min")
    s.add_argument("--train-frac", type=float, default=0.6)
    s.add_argument("--min-attack-flows", type=int, default=5)
    s.add_argument("--z", type=float, default=6.0)
    s.add_argument("--save", help="write the printed results and run metadata as JSON")
    s.set_defaults(fn=cmd_flows)

    s = sub.add_parser("flowmodel", help="per-flow Bot classifier on CIC-IDS2017 (needs pandas and scikit-learn)")
    s.add_argument("--file", default="cicids2017_traffic_label/Friday-WorkingHours-Morning.pcap_ISCX.csv")
    s.add_argument("--train-frac", type=float, default=0.6)
    s.add_argument("--extended", action="store_true", help="run threshold, machine, duplicate, and feature-ablation experiments")
    s.add_argument("--diagnose", action="store_true", help="run source-IP leakage diagnostic experiments")
    s.add_argument("--audit-labels", action="store_true",
                   help="print Bot label counts against documented Friday attack windows")
    s.add_argument("--save", help="write the printed results and run metadata as JSON")
    s.set_defaults(fn=cmd_flowmodel)

    s = sub.add_parser("bench", help="throughput in packets per second")
    s.add_argument("--duration", type=int, default=600)
    s.set_defaults(fn=cmd_bench)

    a = p.parse_args(argv)
    try:
        a.fn(a)
    except (PcapError, ValueError, RuntimeError, FileNotFoundError, PermissionError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
