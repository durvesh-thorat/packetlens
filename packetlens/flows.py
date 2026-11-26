"""Real-data experiment on CIC-IDS2017 flow files (needs pandas).

The flow files describe connections, not packets, so this module does NOT use the packet
parser. It turns flows into a per-minute time series and runs the same volume detectors
(EWMA z-score, Isolation Forest, later a pretrained forecaster) on it.

Protocol: baseline = first part of a clean day (Monday). Clean hold-out = the rest of Monday,
used to count false alarms per hour. Attack data = other days, scored per minute.
"""
import json
import platform
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .evaluate import _prf
from .ml import GraniteForecastDetector, IsolationForestDetector
from .stats import block_bootstrap
from .timeseries import EwmaZScoreDetector

try:
    import pandas as pd
except ImportError as e:     # pragma: no cover
    raise RuntimeError("flow experiments need pandas: pip install pandas") from e

FEATURES = ("flows", "packets", "bytes", "syn", "sources", "dports")
BOOTSTRAP_SEED = 42
REQUIRED = ["Timestamp", "Label", "Source IP", "Destination IP", "Destination Port",
            "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
            "Total Length of Bwd Packets", "SYN Flag Count"]
NUMERIC = REQUIRED[4:]


def load_flows(paths, pm_fix=True):
    """Read one or more flow files into one cleaned DataFrame with a parsed `ts` column.

    Cleaning done here, each one a real quirk of this dataset:
      * latin-1 decoding (a Thursday label contains a non-UTF-8 dash character);
      * header names have stray spaces, so they are stripped;
      * some files repeat the header row in the middle, those rows are dropped;
      * numeric columns hold 'Infinity' and blanks, which become 0;
      * timestamps are day/month/year with NO am/pm marker. The capture ran roughly 09:00 to 17:00,
        so an hour below 8 is an afternoon hour and gets +12 (turn off with pm_fix=False).
    """
    paths = [paths] if isinstance(paths, (str, Path)) else list(paths)
    frames = []
    for p in paths:
        df = pd.read_csv(p, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        missing = [c for c in REQUIRED if c not in df.columns]
        if missing:
            raise ValueError(f"{p}: missing columns {missing}. Is this a flow file with Timestamp and Label?")
        frames.append(df[REQUIRED])
    df = pd.concat(frames, ignore_index=True)
    df = df[df["Label"].astype(str).str.strip() != "Label"]
    for c in NUMERIC:
        df[c] = pd.to_numeric(df[c], errors="coerce").replace([float("inf"), float("-inf")], 0).fillna(0)
    ts = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce")
    if ts.isna().mean() > 0.01:
        raise ValueError("more than 1% of timestamps could not be parsed; check the date format")
    df, ts = df[ts.notna()].copy(), ts[ts.notna()]
    if not set(ts.dt.month.unique()) <= {7}:
        raise ValueError("expected only July 2017 dates; day and month may be swapped")
    if pm_fix:
        ts = ts.where(ts.dt.hour >= 8, ts + pd.Timedelta(hours=12))
    df["ts"] = ts
    df["label"] = (df["Label"].astype(str).str.replace(r"[^\x20-\x7e]", "-", regex=True)
                   .str.replace(r"-+", "-", regex=True).str.strip())
    return df


def to_series(df, freq="1min", min_attack_flows=5):
    """Per-bin features, plus the ground truth. A bin is an attack bin if it holds at least
    `min_attack_flows` attack flows. Returns (series, {label: set(bins)})."""
    d = df.assign(bin=df["ts"].dt.floor(freq))
    d["is_attack"] = d["label"].str.upper() != "BENIGN"
    d["packets"] = d["Total Fwd Packets"] + d["Total Backward Packets"]
    d["bytes"] = d["Total Length of Fwd Packets"] + d["Total Length of Bwd Packets"]
    g = d.groupby("bin")
    out = pd.DataFrame({
        "flows": g.size(), "packets": g["packets"].sum(), "bytes": g["bytes"].sum(),
        "syn": g["SYN Flag Count"].sum(), "sources": g["Source IP"].nunique(),
        "dports": g["Destination Port"].nunique(), "attack_flows": g["is_attack"].sum(),
    })
    out = out.reindex(pd.date_range(out.index.min(), out.index.max(), freq=freq), fill_value=0)
    out["attack"] = out["attack_flows"] >= min_attack_flows
    label_bins = {}
    for (lab, b), n in d[d["is_attack"]].groupby(["label", "bin"]).size().items():
        if n >= min_attack_flows:
            label_bins.setdefault(lab, set()).add(b)
    return out, label_bins


def _records(series):
    return [{"t": idx.timestamp(), **{f: float(row[f]) for f in FEATURES}} for idx, row in series.iterrows()]


def _bootstrap_summary(truth, prediction, *, block_length=5, bin_seconds=60,
                       resamples=1000, seed=BOOTSTRAP_SEED):
    estimate, note = block_bootstrap(
        truth, prediction, block_length=block_length, bin_seconds=bin_seconds,
        resamples=resamples, seed=seed)
    n = len(truth)
    if estimate:
        points = estimate["point"]
    else:
        points = _prf(
            [actual for values in truth for actual in (values if isinstance(values, (list, tuple)) else [values])],
            [predicted for values in prediction for predicted in
             (values if isinstance(values, (list, tuple)) else [values])])
        points["false_alarms_per_hour"] = (
            points["fp"] * 3600 / (n * bin_seconds) if n else None)
    metrics = {}
    names = ("precision", "recall", "f1", "false_alarms_per_hour")
    for name in names:
        metrics[name] = {
            "value": (round(points[name], 3 if name != "false_alarms_per_hour" else 2)
                      if points[name] is not None else None),
            "ci95": ([round(value, 3 if name != "false_alarms_per_hour" else 2)
                      for value in estimate["ci95"][name]] if estimate else None),
            "n": n,
            "note": note,
        }
    return metrics


def evaluate_flows(benign_paths, attack_paths, freq="1min", train_frac=0.6, min_attack_flows=5, z=6.0,
                   contamination=0.01, granite=False):
    if granite and freq != "1min":
        raise ValueError("Granite forecasting requires one-minute bins (--freq 1min)")
    ben, _ = to_series(load_flows(benign_paths), freq, min_attack_flows)
    atk, label_bins = to_series(load_flows(attack_paths), freq, min_attack_flows)
    cut = int(len(ben) * train_frac)
    train, clean = _records(ben.iloc[:cut]), _records(ben.iloc[cut:])
    test = _records(atk)
    hours_clean = len(clean) * pd.Timedelta(freq).total_seconds() / 3600
    truth = [bool(x) for x in atk["attack"]]
    atk_index = list(atk.index)

    preds = {}
    for name, frozen in (("zscore_adaptive", False), ("zscore_frozen", True)):
        zd = EwmaZScoreDetector(metrics=FEATURES, z=z)
        for b in train:
            zd.update(b)
        if frozen:
            zd.freeze()
        zc, za = [], []
        for seq, out in ((clean, zc), (test, za)):
            for b in seq:
                zd.update(b)
                out.append(bool(zd.last_flags))
        preds[name] = (zc, za)
    try:
        clf = IsolationForestDetector(contamination=contamination, features=FEATURES).fit(train)
        preds["isolation_forest"] = (clf.predict(clean), clf.predict(test))
    except RuntimeError:
        pass

    granite_detector = None
    if granite:
        granite_detector = GraniteForecastDetector().fit(train)
        clean_history = train[-granite_detector.CONTEXT_LENGTH:]
        preds["granite"] = (granite_detector.predict(clean, history=clean_history),
                            granite_detector.predict(test))

    result = {"bins": {"train": len(train), "clean_holdout": len(clean), "attack_set": len(test),
                       "attack_bins": sum(truth)}, "methods": {}}
    clean_truth = [False] * len(clean)
    if granite_detector is not None:
        result["granite"] = {
            **granite_detector.metadata,
            "unscored_attack_prefix_bins": min(len(test), granite_detector.CONTEXT_LENGTH),
        }
    for name, (pc, pa) in preds.items():
        flagged = {t for t, p in zip(atk_index, pa) if p}
        clean_hours = (len(clean) * pd.Timedelta(freq).total_seconds() / 3600
                       if name == "granite" else hours_clean)
        metrics = _prf(truth, pa)
        attack_bootstrap = _bootstrap_summary(truth, pa, block_length=5,
                                              bin_seconds=pd.Timedelta(freq).total_seconds())
        clean_bootstrap = _bootstrap_summary(
            clean_truth, pc, block_length=5,
            bin_seconds=pd.Timedelta(freq).total_seconds())
        bootstrap = {
            key: attack_bootstrap[key] for key in ("precision", "recall", "f1")
        }
        bootstrap["false_alarms_per_hour"] = clean_bootstrap["false_alarms_per_hour"]
        family_bootstrap = {}
        family_metrics = {}
        for label, bins in sorted(label_bins.items()):
            family_truth = [timestamp in bins for timestamp in atk_index]
            family_metrics[label] = _prf(family_truth, pa)["recall"]
            family_bootstrap[label] = {
                key: value for key, value in _bootstrap_summary(
                    family_truth, pa, block_length=5,
                    bin_seconds=pd.Timedelta(freq).total_seconds()).items()
                if key in {"precision", "recall", "f1"}
            }
        result["methods"][name] = {
            **metrics,
            "false_alarms_per_hour_on_clean": round(sum(pc) / clean_hours, 2) if clean_hours else None,
            "recall_by_attack": {lab: round(value, 2) for lab, value in family_metrics.items()},
            "bootstrap": bootstrap,
            "bootstrap_by_attack": family_bootstrap,
        }
    return result


def print_report(r):
    b = r["bins"]
    print(f"bins: {b['train']} train, {b['clean_holdout']} clean hold-out, {b['attack_set']} attack set "
          f"({b['attack_bins']} attack bins)")
    labels = sorted({k for m in r["methods"].values() for k in m["recall_by_attack"]})
    def show(value, stats):
        ci = stats["ci95"]
        note = f"; {stats['note']}" if stats["note"] else ""
        interval = f" [{ci[0]}, {ci[1]}]" if ci else ""
        return f"{value}{interval} (n={stats['n']}{note})"

    print("\n| method | precision | recall | F1 | false alarms/hour (clean) |\n|---|---|---|---|---|")
    for n, m in r["methods"].items():
        boot = m["bootstrap"]
        print(f"| {n} | {show(m['precision'], boot['precision'])} "
              f"| {show(m['recall'], boot['recall'])} | {show(m['f1'], boot['f1'])} "
              f"| {show(m['false_alarms_per_hour_on_clean'], boot['false_alarms_per_hour'])} |")
    if labels:
        print("\nPer-attack-family precision, recall and F1")
        print("| attack | method | precision | recall | F1 |")
        print("|---|---|---|---|---|")
        for lab in labels:
            for name, method in r["methods"].items():
                metrics = method["bootstrap_by_attack"].get(lab)
                if metrics:
                    print(f"| {lab} | {name} | {show(metrics['precision']['value'], metrics['precision'])} "
                          f"| {show(metrics['recall']['value'], metrics['recall'])} "
                          f"| {show(metrics['f1']['value'], metrics['f1'])} |")
    if "granite" in r:
        g = r["granite"]
        print(f"\nGranite revision: {g['revision']} (context {g['context_length']}, horizon {g['horizon']} bins)")
        print(f"False-alarm budget: {g['false_alarm_budget_per_hour']} per hour (Monday train only)")
        print("Caveat: forecast context can contain attack bins (the adaptive-baseline pollution problem).")


def save_report(result, path, train_frac, freq, meta=None):
    try:
        sklearn_version = version("scikit-learn")
    except PackageNotFoundError:
        sklearn_version = None
    payload = {
        **result,
        "seed": 0,
        "train_frac": train_frac,
        "bin_width": freq,
        "library_versions": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
            "pandas": pd.__version__,
            "scikit-learn": sklearn_version,
        },
    }
    if meta is not None:
        payload["meta"] = meta
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
