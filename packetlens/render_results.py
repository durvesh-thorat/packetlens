"""Generate Markdown result tables and the README headline section from JSON."""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
README_PATH = ROOT / "README.md"
RESULTS_PATH = ROOT / "docs" / "RESULTS.md"
README_START = "<!-- RESULTS:START -->"
README_END = "<!-- RESULTS:END -->"


def _value(value):
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True)
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers, rows):
    lines = [
        "| " + " | ".join(_value(value) for value in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_value(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def _section(title, headers, rows):
    if not rows:
        return f"### {title}\n\n_No data recorded._"
    return f"### {title}\n\n{_table(headers, rows)}"


def _metric_text(value, uncertainty):
    if not uncertainty:
        return _value(value)
    interval = uncertainty.get("ci95")
    text = _value(value)
    if interval:
        text += f" [{_value(interval[0])}, {_value(interval[1])}]"
    text += f" (n={_value(uncertainty.get('n'))}"
    if uncertainty.get("note"):
        text += f"; {_value(uncertainty['note'])}"
    return text + ")"


def _provenance(report):
    meta = report.get("meta")
    if not isinstance(meta, dict):
        return "Run provenance was not recorded in this result file."
    rows = [
        ["Command line", meta.get("command_line")],
        ["UTC time", meta.get("utc_time")],
    ]
    for package, version in (meta.get("versions") or {}).items():
        rows.append([f"Version: {package}", version])
    for name, value in (meta.get("seeds") or {}).items():
        rows.append([f"Seed: {name}", value])
    for file in meta.get("dataset_files") or []:
        rows.append([
            "Dataset file",
            f"{file.get('name')} — {file.get('status')}; {file.get('size_bytes')} bytes; "
            f"SHA-256 {file.get('sha256')}",
        ])
    for skipped in meta.get("skipped") or []:
        rows.append(["Skipped", skipped])
    return _section("Provenance", ["Field", "Value"], rows)


def _flatten(value, prefix=""):
    rows = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(_flatten(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            rows.extend(_flatten(item, f"{prefix}[{index}]"))
    else:
        rows.append([prefix, value])
    return rows


def _evaluation(report):
    parts = []
    parts.append(_section(
        "Event detection",
        ["Event", "Detector", "Detected", "Delay (s)"],
        [[row.get(key) for key in ("event", "detector", "detected", "delay_s")]
         for row in report.get("events", [])],
    ))
    parts.append(_section(
        "Alert and traffic totals",
        ["Measure", "Value"],
        [[key, value] for key, value in report.items()
         if key not in {"events", "false_positives_on_clean_traffic",
                        "false_positive_details", "bin_level_volume_detectors", "meta"}],
    ))
    parts.append(_section(
        "Clean-traffic false positives",
        ["Detector", "Count"],
        [[name, count] for name, count in
         (report.get("false_positives_on_clean_traffic") or {}).items()],
    ))
    detectors = report.get("bin_level_volume_detectors") or {}
    parts.append(_section(
        "Bin-level volume detectors",
        ["Method", "Precision", "Recall", "F1", "TP", "FP", "FN"],
        [[name, *(result.get(key) for key in ("precision", "recall", "f1", "tp", "fp", "fn"))]
         if result else [name, "unavailable", "unavailable", "unavailable", None, None, None]
         for name, result in detectors.items()],
    ))
    if report.get("false_positive_details"):
        parts.append(_section(
            "False-positive details",
            ["Detail"],
            [[detail] for detail in report["false_positive_details"]],
        ))
    return parts


def _benchmark(report):
    return [_section(
        "Throughput benchmark",
        ["Measurement", "Value"],
        [[key, value] for key, value in report.items() if key != "meta"],
    )]


def _flows(report):
    parts = [
        _section("Bin counts", ["Set", "Bins"],
                 [[key, value] for key, value in (report.get("bins") or {}).items()]),
    ]
    rows = []
    for method, metrics in (report.get("methods") or {}).items():
        uncertainty = metrics.get("bootstrap") or {}
        rows.append([
            method,
            *[_metric_text(metrics.get(key), uncertainty.get(key))
              for key in ("precision", "recall", "f1")],
            _metric_text(metrics.get("false_alarms_per_hour_on_clean"),
                         uncertainty.get("false_alarms_per_hour")),
        ])
    parts.append(_section(
        "Overall detector metrics",
        ["Method", "Precision", "Recall", "F1", "False alarms/hour (clean)"],
        rows,
    ))
    labels = sorted({
        label for metrics in (report.get("methods") or {}).values()
        for label in (metrics.get("recall_by_attack") or {})
    })
    family_rows = []
    recall_rows = []
    for label in labels:
        for method, metrics in (report.get("methods") or {}).items():
            values = (metrics.get("bootstrap_by_attack") or {}).get(label)
            if values:
                family_rows.append([
                    label, method,
                    *[_metric_text(values.get(key, {}).get("value"), values.get(key))
                      for key in ("precision", "recall", "f1")],
                ])
            if label in (metrics.get("recall_by_attack") or {}):
                recall_rows.append([label, method, metrics["recall_by_attack"][label]])
    if family_rows:
        parts.append(_section(
            "Metrics by attack family",
            ["Attack family", "Method", "Precision", "Recall", "F1"],
            family_rows,
        ))
    elif recall_rows:
        parts.append(_section("Recall by attack family", ["Attack family", "Method", "Recall"],
                              recall_rows))
    if report.get("granite"):
        parts.append(_section(
            "Granite run details",
            ["Field", "Value"],
            [[key, value] for key, value in report["granite"].items()],
        ))
    return parts


def _flowmodel(report):
    parts = []
    count_rows = [
        [split, label, count]
        for split, labels in (report.get("counts") or {}).items()
        for label, count in labels.items()
    ]
    parts.append(_section("Train/test counts", ["Split", "Class", "Flows"], count_rows))
    result_rows = []
    for row in report.get("results", []):
        metrics = row.get("metrics") or {}
        uncertainty = metrics.get("bootstrap") or {}
        result_rows.append([
            row.get("model"),
            *[_metric_text(metrics.get(key), uncertainty.get(key))
              for key in ("precision", "recall", "f1")],
            metrics.get("average_precision"),
            metrics.get("fp"),
            metrics.get("fn"),
            _metric_text(metrics.get("false_alarms_per_hour"),
                         uncertainty.get("false_alarms_per_hour")),
        ])
    parts.append(_section(
        "Model results",
        ["Model", "Precision", "Recall", "F1", "Average precision", "FP", "FN",
         "False alarms/hour"],
        result_rows,
    ))

    duplicate_check = report.get("duplicate_check") or {}
    duplicate_rows = []
    for label, values in (duplicate_check.get("per_class") or {}).items():
        duplicate_rows.append([
            label, values.get("test_rows"), values.get("exact_duplicates"),
            values.get("exact_duplicate_rate"), values.get("duplicate_free_rows"),
        ])
    if not duplicate_rows:
        counts = report.get("counts") or {}
        duplicates = report.get("exact_test_feature_vectors_in_training") or {}
        for label, count in duplicates.items():
            total = (counts.get("test") or {}).get(label)
            duplicate_rows.append([
                label, total, count, count / total if total else None,
                total - count if total is not None else None,
            ])
    parts.append(_section(
        "Exact train/test feature duplicates",
        ["Class", "Test rows", "Exact duplicates", "Rate", "Duplicate-free rows"],
        duplicate_rows,
    ))
    duplicate_free = duplicate_check.get("duplicate_free_test") or {}
    if duplicate_free:
        metrics = duplicate_free.get("metrics") or {}
        parts.append(_section(
            "Duplicate-free test metrics",
            ["Rows", "Precision", "Recall", "F1", "False positives"],
            [[duplicate_free.get("rows"), metrics.get("precision"), metrics.get("recall"),
              metrics.get("f1"), metrics.get("fp")]],
        ))
    parts.append(_section(
        "Top feature importances",
        ["Feature", "Importance"],
        [[item.get("feature"), item.get("importance")]
         for item in report.get("top_10_feature_importances", [])],
    ))
    if report.get("audit"):
        parts.append(_section("Label-window audit", ["Field", "Value"],
                              _flatten(report["audit"])))
    if report.get("diagnostics"):
        parts.append(_section("Cleaner split diagnostics", ["Field", "Value"],
                              _flatten(report["diagnostics"])))
    return parts


def _report_caveat(name):
    if name == "evaluation.json":
        return ("Synthetic traffic and labels are generated together; these results are optimistic "
                "and are not an estimate of field performance.")
    if name == "benchmark.json":
        return "Throughput varies with hardware, Python build, and system load."
    if name == "flows_real.json":
        return ("CIC-IDS2017 flow tables are aggregated into one-minute bins; this is not packet "
                "pipeline evaluation. Attack bins require at least five labelled attack flows.")
    if name.startswith("flowmodel_"):
        return ("Per-flow results use a chronological split and can reflect dataset label artifacts "
                "and exact feature duplicates; see the duplicate check and label-window audit.")
    return "Interpret this result only within its recorded dataset and split."


def _render_one(name, report):
    if name == "evaluation.json":
        tables = _evaluation(report)
    elif name == "benchmark.json":
        tables = _benchmark(report)
    elif name == "flows_real.json":
        tables = _flows(report)
    elif name.startswith("flowmodel_"):
        tables = _flowmodel(report)
    else:
        tables = [_section("Result data", ["Field", "Value"], _flatten(
            {key: value for key, value in report.items() if key != "meta"}))]
    return "\n\n".join([
        f"## {name}",
        _provenance(report),
        *tables,
        "### Caveats\n\n" + _report_caveat(name)
        + " See [the evaluation protocol](EVALUATION_PROTOCOL.md) and "
        "[limitations](LIMITATIONS.md).",
    ])


def _readme_metric(row, metric):
    metrics = row.get("metrics") or {}
    value = metrics.get(metric)
    uncertainty = (metrics.get("bootstrap") or {}).get(metric)
    return _metric_text(value, uncertainty)


def _random_forest(report):
    return next((row for row in report.get("results", [])
                 if row.get("model") == "Random forest"), None)


def _flowmodel_headline(report):
    forest = _random_forest(report)
    if not forest:
        return "No Random Forest result is recorded."
    label = report.get("attack_label", "Bot")
    metrics = forest.get("metrics") or {}
    duplicate_check = report.get("duplicate_check") or {}
    per_class = duplicate_check.get("per_class") or {}
    duplicate_free = duplicate_check.get("duplicate_free_test") or {}
    attack_duplicates = per_class.get(label) or {}
    benign_duplicates = per_class.get("BENIGN") or {}
    clean_metrics = duplicate_free.get("metrics") or {}
    note = (
        f"Exact duplicates: {label} {attack_duplicates.get('exact_duplicate_rate', 'not recorded')}, "
        f"BENIGN {benign_duplicates.get('exact_duplicate_rate', 'not recorded')}; "
        f"duplicate-free test P={clean_metrics.get('precision', 'not recorded')}, "
        f"R={clean_metrics.get('recall', 'not recorded')} "
        f"(n={duplicate_free.get('rows', 'not recorded')})."
    )
    return (
        f"{label} Random Forest: P={_readme_metric(forest, 'precision')}, "
        f"R={_readme_metric(forest, 'recall')}, F1={_readme_metric(forest, 'f1')}. "
        f"{note}"
    )


def render_readme_section(results_dir=RESULTS_DIR):
    results_dir = Path(results_dir)
    rows = []
    evaluation_path = results_dir / "evaluation.json"
    if evaluation_path.is_file():
        report = json.loads(evaluation_path.read_text(encoding="utf-8"))
        detected = sum(bool(row.get("detected")) for row in report.get("events", []))
        total = len(report.get("events", []))
        rows.append(["Synthetic packet evaluation",
                     f"{detected}/{total} events detected; alert precision "
                     f"{_value(report.get('alert_precision'))}."])
    benchmark_path = results_dir / "benchmark.json"
    if benchmark_path.is_file():
        report = json.loads(benchmark_path.read_text(encoding="utf-8"))
        rows.append(["Throughput benchmark",
                     f"Parse { _value(report.get('parse_only_pps')) } packets/s; "
                     f"pipeline {_value(report.get('full_pipeline_pps'))} packets/s."])
    flows_path = results_dir / "flows_real.json"
    if flows_path.is_file():
        report = json.loads(flows_path.read_text(encoding="utf-8"))
        rows.append(["Per-minute flow detectors",
                     "; ".join(
                         f"{method}: P={_metric_text(metrics.get('precision'), (metrics.get('bootstrap') or {}).get('precision'))}, "
                         f"R={_metric_text(metrics.get('recall'), (metrics.get('bootstrap') or {}).get('recall'))}"
                         for method, metrics in report.get("methods", {}).items()
                     )])
    for filename in ("flowmodel_real.json", "flowmodel_portscan.json", "flowmodel_ddos.json"):
        path = results_dir / filename
        if path.is_file():
            report = json.loads(path.read_text(encoding="utf-8"))
            rows.append([filename, _flowmodel_headline(report)])
    if not rows:
        rows.append(["Results", "No result JSON files are available."])
    return "\n".join([
        "### Current evidence",
        "",
        _table(["Experiment", "Headline"], rows),
    ])


def render_results(results_dir=RESULTS_DIR, readme_path=README_PATH,
                   results_path=RESULTS_PATH):
    results_dir, readme_path, results_path = (
        Path(results_dir), Path(readme_path), Path(results_path))
    reports = []
    for path in sorted(results_dir.glob("*.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            report = {"result": report}
        reports.append(_render_one(path.name, report))
    markdown = "# PacketLens evaluation results\n\n" + (
        "\n\n".join(reports) if reports else "_No result JSON files are available._")
    section = render_readme_section(results_dir)
    readme = readme_path.read_text(encoding="utf-8")
    if readme.count(README_START) != 1 or readme.count(README_END) != 1:
        raise ValueError(f"{readme_path}: expected exactly one generated-results marker pair")
    start = readme.index(README_START) + len(README_START)
    end = readme.index(README_END)
    if start > end:
        raise ValueError(f"{readme_path}: generated-results markers are out of order")
    updated = readme[:start] + "\n" + section + "\n" + readme[end:]
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(markdown.rstrip() + "\n", encoding="utf-8")
    readme_path.write_text(updated, encoding="utf-8")
    return results_path, readme_path
