"""Re-run the published experiments and compare them before writing results."""
import copy
import importlib.util
import json
import subprocess
from pathlib import Path

from .evaluate import benchmark, evaluate, print_report
from .provenance import build_meta


FLOW_FILES = (
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
)
FLOWMODEL_FILES = {
    "flowmodel_real.json": ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "Bot", True, True),
    "flowmodel_audit.json": ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "Bot", True, True),
    "flowmodel_portscan.json": ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                                "PortScan", False, False),
    "flowmodel_ddos.json": ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                            "DDoS", False, False),
}


def _render_json(value):
    return json.dumps(value, indent=2, allow_nan=False) + "\n"


_MISSING = object()


def _differences(before, after, path=""):
    if isinstance(before, dict) and isinstance(after, dict):
        keys = sorted(set(before) | set(after))
        for key in keys:
            if key == "meta":
                continue
            child = f"{path}.{key}" if path else key
            yield from _differences(before.get(key, _MISSING), after.get(key, _MISSING), child)
    elif isinstance(before, list) and isinstance(after, list):
        for index in range(max(len(before), len(after))):
            old = before[index] if index < len(before) else _MISSING
            new = after[index] if index < len(after) else _MISSING
            yield from _differences(old, new, f"{path}[{index}]")
    elif before != after:
        yield path, before, after


def _display(value):
    return "<missing>" if value is _MISSING else repr(value)


def _committed_result(path):
    repo_root = Path(__file__).resolve().parents[1]
    try:
        relative = path.resolve().relative_to(repo_root)
    except ValueError:
        return None
    result = subprocess.run(
        ["git", "show", f"HEAD:{relative.as_posix()}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError(
            f"cannot read committed baseline {relative.as_posix()}: {result.stderr.strip()}")
    return result.stdout


def _save_or_compare(results_dir, filename, result, write):
    path = results_dir / filename
    print(f"\n{'Writing' if write else 'Would write'} {path.as_posix()}")
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_render_json(result), encoding="utf-8")
        print("  saved")
        return
    committed = _committed_result(path)
    if committed is None:
        print("  committed result: missing")
        return
    try:
        previous = json.loads(committed)
    except json.JSONDecodeError as exc:
        raise ValueError(f"committed results/{filename} is not valid JSON: {exc}") from exc
    differences = list(_differences(previous, result))
    if differences:
        for key, old, new in differences:
            print(f"  {key}: {_display(old)} -> {_display(new)}")
    else:
        print("  numeric values: unchanged")
    if previous.get("meta") != result.get("meta"):
        print("  meta: would be refreshed (command, UTC time, versions, seeds, dataset hashes)")


def _meta(command_line, paths, seeds, skipped=()):
    return build_meta(command_line, paths, seeds=seeds, skipped=skipped)


def _run_flows(data_dir, output_dir, write, command_line):
    files = [data_dir / name for name in FLOW_FILES]
    missing = [path.name for path in files if not path.is_file()]
    if missing:
        print(f"\nSKIPPED flows_real.json: missing dataset file(s): {', '.join(missing)}")
        return
    try:
        from .flows import evaluate_flows, print_report
    except RuntimeError as exc:
        print(f"\nSKIPPED flows_real.json: {exc}")
        return

    granite_available = all(importlib.util.find_spec(name) is not None
                            for name in ("torch", "tsfm_public"))
    skipped = [] if granite_available else ["Granite: optional torch/tsfm_public packages unavailable"]
    if not granite_available:
        print("\nSKIPPED Granite forecaster: optional torch/tsfm_public packages unavailable")
    meta = _meta(command_line, files, {
        "isolation_forest": 0,
        "bootstrap": 42,
        "granite": "model revision controls inference",
    }, skipped)
    result = evaluate_flows(
        files[0], files[1:], freq="1min", train_frac=0.6,
        min_attack_flows=5, z=6.0, granite=granite_available)
    print_report(result)
    result.update({
        "seed": 0,
        "train_frac": 0.6,
        "bin_width": "1min",
        "library_versions": meta["versions"],
        "meta": meta,
    })
    _save_or_compare(output_dir, "flows_real.json", result, write)


def _run_flowmodels(data_dir, output_dir, write, command_line):
    bot_filename = FLOWMODEL_FILES["flowmodel_real.json"][0]
    bot_path = data_dir / bot_filename
    bot_available = bot_path.is_file()
    if not bot_available:
        print(f"\nSKIPPED flowmodel_real.json and flowmodel_audit.json: missing dataset file {bot_filename}")

    attack_files = {}
    for output_name in ("flowmodel_portscan.json", "flowmodel_ddos.json"):
        filename = FLOWMODEL_FILES[output_name][0]
        source = data_dir / filename
        if source.is_file():
            attack_files[output_name] = source
        else:
            print(f"\nSKIPPED {output_name}: missing dataset file {filename}")

    if not bot_available and not attack_files:
        return
    available = all(importlib.util.find_spec(name) is not None
                    for name in ("numpy", "pandas", "sklearn"))
    if not available:
        reason = "numpy, pandas, and scikit-learn are required"
        for output_name in ("flowmodel_real.json", "flowmodel_audit.json"):
            if bot_available:
                print(f"\nSKIPPED {output_name}: {reason}")
        for output_name in attack_files:
            print(f"\nSKIPPED {output_name}: {reason}")
        return

    from .flowmodel import run_experiment

    if bot_available:
        bot_meta = _meta(command_line, [bot_path], {
            "random_forest": 42, "isolation_forest": 42, "bootstrap": 42,
        })
        bot_result = run_experiment(
            bot_path, audit_labels=True, diagnose=True, attack_label="Bot", meta=bot_meta)
        real_result = copy.deepcopy(bot_result)
        real_result.pop("audit", None)
        _save_or_compare(output_dir, "flowmodel_real.json", real_result, write)
        _save_or_compare(output_dir, "flowmodel_audit.json", bot_result, write)

    for output_name, source in attack_files.items():
        _filename, label, _audit, _diagnose = FLOWMODEL_FILES[output_name]
        result = run_experiment(
            source, attack_label=label,
            meta=_meta(command_line, [source], {
                "random_forest": 42, "isolation_forest": 42, "bootstrap": 42,
            }))
        _save_or_compare(output_dir, output_name, result, write)


def reproduce(data_dir="cicids2017_traffic_label", *, skip_real=False, write=False,
              command_line="python -m packetlens reproduce", results_dir="results"):
    """Run synthetic checks and optionally the real-data experiments."""
    data_dir, output_dir = Path(data_dir), Path(results_dir)
    print("PacketLens reproduction: " + ("WRITE ENABLED" if write else "DRY RUN"))
    evaluation = evaluate()
    print_report(evaluation)
    evaluation["meta"] = _meta(
        command_line, (), {"benign_traffic": 7, "attack_traffic": 8})
    _save_or_compare(output_dir, "evaluation.json", evaluation, write)

    benchmark_result = benchmark()
    print("\nBenchmark:")
    print(_render_json(benchmark_result), end="")
    benchmark_result["meta"] = _meta(command_line, (), {"benign_traffic": 3})
    _save_or_compare(output_dir, "benchmark.json", benchmark_result, write)

    if skip_real:
        print("\nSKIPPED real-data experiments: --skip-real")
    else:
        _run_flows(data_dir, output_dir, write, command_line)
        _run_flowmodels(data_dir, output_dir, write, command_line)
    return 0
