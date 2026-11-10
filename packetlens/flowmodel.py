"""Per-flow Bot classification experiment for CIC-IDS2017 (optional dependencies)."""
import csv
import ipaddress
import json
import platform
from datetime import time as clock_time
from importlib.metadata import version
from pathlib import Path

try:
    from joblib import parallel_backend
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.dummy import DummyClassifier
    from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                                 precision_score, recall_score)
    from sklearn.preprocessing import StandardScaler
except ImportError as e:  # pragma: no cover - depends on optional environment
    raise RuntimeError("flowmodel requires pandas and scikit-learn: pip install pandas scikit-learn") from e


DEFAULT_FILE = Path("cicids2017_traffic_label") / "Friday-WorkingHours-Morning.pcap_ISCX.csv"
RANDOM_STATE = 42
# Schedule documented at https://www.unb.ca/cic/datasets/ids-2017.html
FRIDAY_ATTACK_WINDOWS = {
    "Botnet": ((clock_time(10, 2), clock_time(11, 2)),),
    "PortScan": (
        (clock_time(13, 55), clock_time(13, 57)),
        (clock_time(13, 58), clock_time(14, 0)),
        (clock_time(14, 1), clock_time(14, 4)),
        (clock_time(14, 5), clock_time(14, 7)),
        (clock_time(14, 8), clock_time(14, 10)),
        (clock_time(14, 11), clock_time(14, 13)),
        (clock_time(14, 14), clock_time(14, 16)),
        (clock_time(14, 17), clock_time(14, 19)),
        (clock_time(14, 20), clock_time(14, 21)),
        (clock_time(14, 22), clock_time(14, 24)),
        (clock_time(14, 33), clock_time(14, 33)),
        (clock_time(14, 35), clock_time(14, 35)),
        (clock_time(14, 51), clock_time(14, 53)),
        (clock_time(14, 54), clock_time(14, 56)),
        (clock_time(14, 57), clock_time(14, 59)),
        (clock_time(15, 0), clock_time(15, 2)),
        (clock_time(15, 3), clock_time(15, 5)),
        (clock_time(15, 6), clock_time(15, 7)),
        (clock_time(15, 8), clock_time(15, 10)),
        (clock_time(15, 11), clock_time(15, 12)),
        (clock_time(15, 13), clock_time(15, 15)),
        (clock_time(15, 16), clock_time(15, 18)),
        (clock_time(15, 19), clock_time(15, 21)),
        (clock_time(15, 22), clock_time(15, 24)),
        (clock_time(15, 25), clock_time(15, 25)),
        (clock_time(15, 26), clock_time(15, 27)),
        (clock_time(15, 28), clock_time(15, 29)),
    ),
    "DDoS": ((clock_time(15, 56), clock_time(16, 16)),),
}
IDENTIFIER_COLUMNS = {
    "Flow ID", "Source IP", "Destination IP", "Source Port", "Destination Port", "Timestamp",
}


def load_flow_data(path):
    """Load all fields, clean CIC-IDS2017 quirks, and retain only Bot and BENIGN flows."""
    path = Path(path)
    with path.open(encoding="latin-1", newline="") as source:
        original_columns = next(csv.reader(source), None)
    if not original_columns:
        raise ValueError(f"{path}: missing CSV header")

    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    if len(original_columns) != len(df.columns):
        raise ValueError(f"{path}: CSV header and data have different column counts")
    cleaned_columns = [column.strip() for column in original_columns]
    keep_positions, seen = [], set()
    for position, column in enumerate(cleaned_columns):
        if column not in seen:
            keep_positions.append(position)
            seen.add(column)
    df = df.iloc[:, keep_positions].copy()
    df.columns = [cleaned_columns[position] for position in keep_positions]

    missing = {"Timestamp", "Label"} - set(df.columns)
    if missing:
        raise ValueError(f"{path}: missing required columns {sorted(missing)}")

    df = df[df["Label"].astype(str).str.strip() != "Label"].copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    normalized_labels = (df["Label"].astype(str).str.replace(r"[^\x20-\x7e]", "-", regex=True)
                         .str.replace(r"-+", "-", regex=True).str.strip())
    normalized_upper = normalized_labels.str.upper()
    recognized = normalized_upper.isin({"BOT", "BENIGN"})
    dropped_labels = int((~recognized).sum())
    df = df.loc[recognized].copy()
    normalized_upper = normalized_upper.loc[recognized]
    timestamps = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce")
    if timestamps.isna().mean() > 0.01:
        raise ValueError(f"{path}: more than 1% of timestamps could not be parsed")
    valid_timestamps = timestamps.notna()
    df, timestamps = df.loc[valid_timestamps].copy(), timestamps.loc[valid_timestamps]
    normalized_upper = normalized_upper.loc[valid_timestamps]
    normalized_labels = normalized_labels.loc[valid_timestamps]
    timestamps = timestamps.where(timestamps.dt.hour >= 8, timestamps + pd.Timedelta(hours=12))
    df["ts"] = timestamps
    df["label"] = normalized_labels
    df["target"] = normalized_upper.map({"BENIGN": 0, "BOT": 1}).astype(int)

    non_numeric = IDENTIFIER_COLUMNS | {"Label", "label", "target", "ts"}
    for column in df.columns:
        if column not in non_numeric:
            df[column] = pd.to_numeric(df[column], errors="coerce").replace([np.inf, -np.inf], np.nan)
    return df, dropped_labels


def feature_columns(df, include_destination_port=False):
    """Return numeric model features, excluding identifiers (except explicit port sensitivity)."""
    excluded = IDENTIFIER_COLUMNS - ({"Destination Port"} if include_destination_port else set())
    excluded |= {"Label", "label", "target", "ts"}
    return [
        column for column in df.columns
        if column not in excluded
        and pd.api.types.is_numeric_dtype(df[column])
        and df[column].notna().any()
    ]


def time_split(df, train_frac=0.6):
    """Sort chronologically and split at the first train_frac of rows."""
    if not 0 < train_frac < 1:
        raise ValueError("train-frac must be greater than 0 and less than 1")
    ordered = df.sort_values("ts", kind="mergesort").reset_index(drop=True)
    cut = int(len(ordered) * train_frac)
    if cut == 0 or cut == len(ordered):
        raise ValueError("time split must leave at least one row in train and test")
    return ordered.iloc[:cut].copy(), ordered.iloc[cut:].copy()


def _prepare_features(train, test, candidates):
    constant = [column for column in candidates if train[column].nunique(dropna=True) <= 1]
    selected = [column for column in candidates if column not in constant]
    if not selected:
        raise ValueError("no non-constant numeric training features are available")
    imputer = SimpleImputer(strategy="median")
    train_values = imputer.fit_transform(train[selected])
    test_values = imputer.transform(test[selected])
    scaler = StandardScaler()
    return scaler.fit_transform(train_values), scaler.transform(test_values), selected


def _matching_training_rows(train_values, test_values):
    training_vectors = {tuple(row) for row in train_values}
    return np.fromiter((tuple(row) in training_vectors for row in test_values), dtype=bool,
                       count=len(test_values))


def _metrics(y_true, prediction, score):
    tn, fp, fn, tp = confusion_matrix(y_true, prediction, labels=[0, 1]).ravel()
    benign_count = int((np.asarray(y_true) == 0).sum())
    return {
        "precision": precision_score(y_true, prediction, zero_division=0),
        "recall": recall_score(y_true, prediction, zero_division=0),
        "f1": f1_score(y_true, prediction, zero_division=0),
        "average_precision": average_precision_score(y_true, score),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fp_per_1000_benign": fp * 1000 / benign_count if benign_count else 0.0,
    }


def _call_model(method, *args):
    with parallel_backend("threading"):
        return method(*args)


def _report_row(name, result):
    return (f"| {name} | {result['precision']:.4f} | {result['recall']:.4f} | {result['f1']:.4f} "
            f"| {result['average_precision']:.4f} | {result['tn']} | {result['fp']} | {result['fn']} "
            f"| {result['tp']} | {result['fp_per_1000_benign']:.2f} |")


def _new_forest(n_jobs=-1):
    return RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample",
                                 n_jobs=n_jobs, random_state=RANDOM_STATE)


def _positive_probability(model, features):
    classes = list(model.classes_)
    if 1 not in classes:
        return np.zeros(len(features))
    return _call_model(model.predict_proba, features)[:, classes.index(1)]


def _predict_sequentially(model, features):
    """Run diagnostics serially to avoid spawning a worker pool for small reports."""
    jobs = model.n_jobs
    try:
        model.n_jobs = 1
        return model.predict(features)
    finally:
        model.n_jobs = jobs


def _metrics_from_scores(y_true, scores, threshold=0.5):
    return _metrics(y_true, scores >= threshold, scores)


def _in_time_windows(timestamps, windows):
    return timestamps.dt.time.map(
        lambda value: any(start <= value <= end for start, end in windows)
    )


def _audit_label_windows(df, test, test_prediction, forest_metrics):
    if not {"Source IP", "Destination IP", "Destination Port"}.issubset(df.columns):
        raise ValueError("label-window audit requires Source IP, Destination IP, and Destination Port")

    bot_rows = df.loc[df["target"] == 1]
    private_network = ipaddress.ip_network("192.168.0.0/16")
    attacker_ips = set()
    for value in bot_rows["Source IP"].dropna().unique():
        address = str(value).strip()
        if address and ipaddress.ip_address(address) not in private_network:
            attacker_ips.add(address)
    attacker_ips = sorted(attacker_ips)
    if not attacker_ips:
        raise ValueError("label-window audit could not derive a non-192.168/16 Bot IP")

    bot_windows = FRIDAY_ATTACK_WINDOWS["Botnet"]
    bot_times = bot_rows["ts"]
    bot_inside = _in_time_windows(bot_times, bot_windows)
    bot_slots = bot_rows.assign(
        _slot=bot_rows["ts"].dt.floor("30min"), _inside=bot_inside.to_numpy()
    )
    h1 = []
    print("\n\n=== H1. Bot flows per 30-minute slot ===")
    print("| slot | inside | outside |")
    print("|---|---:|---:|")
    for slot, rows in bot_slots.groupby("_slot", sort=True):
        inside_count = int(rows["_inside"].sum())
        outside_count = len(rows) - inside_count
        h1.append({"slot": slot.strftime("%Y-%m-%d %H:%M"),
                   "inside": inside_count, "outside": outside_count})
        print(f"| {slot:%Y-%m-%d %H:%M} | {inside_count} | {outside_count} |")

    window_end = max(end for _, end in bot_windows)
    after_window = df.loc[df["ts"].dt.time > window_end]
    h2 = {}
    print("\n\n=== H2. Attacker-IP flows after window end ===")
    print(f"attacker_ips: {', '.join(attacker_ips)}")
    for attacker_ip in attacker_ips:
        involved = after_window.loc[
            (after_window["Source IP"].astype(str).str.strip() == attacker_ip)
            | (after_window["Destination IP"].astype(str).str.strip() == attacker_ip)
        ].copy()
        involved["_slot"] = involved["ts"].dt.floor("30min")
        counts = []
        print(f"attacker_ip: {attacker_ip}")
        print("| slot | BENIGN | Bot |")
        print("|---|---:|---:|")
        for slot, rows in involved.groupby("_slot", sort=True):
            benign_count = int((rows["target"] == 0).sum())
            bot_count = int((rows["target"] == 1).sum())
            counts.append({"slot": slot.strftime("%Y-%m-%d %H:%M"),
                           "BENIGN": benign_count, "Bot": bot_count})
            print(f"| {slot:%Y-%m-%d %H:%M} | {benign_count} | {bot_count} |")
        benign_after = int((involved["target"] == 0).sum())
        print(f"BENIGN_after_window: {benign_after}")
        print(f"any_BENIGN_after_window: {int(benign_after > 0)}")
        h2[attacker_ip] = {"slots": counts, "BENIGN_after_window": benign_after,
                           "any_BENIGN_after_window": benign_after > 0}

    inside_pairs = set(
        zip(bot_rows.loc[bot_inside, "Destination IP"],
            bot_rows.loc[bot_inside, "Destination Port"])
    )
    outside_rows = bot_rows.loc[~bot_inside]
    outside_pairs = set(zip(outside_rows["Destination IP"], outside_rows["Destination Port"]))
    overlap = len(outside_pairs & inside_pairs)
    fraction = overlap / len(outside_pairs) if outside_pairs else 0.0
    print("\n\n=== H3. Bot destination pairs outside window ===")
    print(f"distinct_outside_pairs: {len(outside_pairs)}")
    print(f"pairs_also_inside: {overlap}")
    print(f"fraction_also_inside: {fraction:.6f}")

    test_inside = _in_time_windows(test["ts"], bot_windows).to_numpy()
    test_bot = test["target"].to_numpy() == 1
    prediction = np.asarray(test_prediction) == 1
    h4 = {}
    print("\n\n=== H4. Test Bot recall by documented window ===")
    print("model: Random forest")
    print("threshold: 0.5")
    print(f"precision: {forest_metrics['precision']:.4f}")
    print("| split | tp | fn |")
    print("|---|---:|---:|")
    for name, mask in (("inside", test_inside), ("outside", ~test_inside)):
        selected = test_bot & mask
        tp = int((selected & prediction).sum())
        fn = int((selected & ~prediction).sum())
        h4[name] = {"tp": tp, "fn": fn}
        print(f"| {name} | {tp} | {fn} |")

    return {
        "attacker_ips": attacker_ips,
        "h1_bot_flows_per_30min": h1,
        "h2_attacker_flows_after_window": h2,
        "h3_destination_pairs": {
            "distinct_outside_pairs": len(outside_pairs),
            "pairs_also_inside": overlap,
            "fraction_also_inside": round(fraction, 6),
        },
        "h4_test_bot": {
            "model": "Random forest", "threshold": 0.5,
            "precision": round(forest_metrics["precision"], 4), **h4,
        },
    }


def select_alarm_threshold(validation_labels, validation_scores, budget):
    """Choose the lowest validation-score threshold within a benign false-alarm budget."""
    labels = np.asarray(validation_labels)
    scores = np.asarray(validation_scores)
    benign_count = int((labels == 0).sum())
    if benign_count == 0:
        return None, None
    thresholds = np.append(np.unique(scores), np.nextafter(np.max(scores), np.inf))
    for threshold in thresholds:
        false_alarms = int(((scores >= threshold) & (labels == 0)).sum())
        rate = false_alarms * 1000 / benign_count
        if rate <= budget:
            return float(threshold), rate
    return None, None


def split_held_out_machines(df, target_fraction=0.4):
    """Hold out complete Bot source-IP groups whose combined Bot count nears target_fraction."""
    bot_counts = df.loc[df["target"] == 1].groupby("Source IP", dropna=False).size()
    ordered = sorted(bot_counts.items(), key=lambda item: str(item[0]))
    if not ordered:
        raise ValueError("held-out-machine split requires Bot flows with Source IP values")

    subsets = {0: ()}
    for ip, count in ordered:
        for subtotal, selected in list(subsets.items()):
            new_total = subtotal + int(count)
            subsets.setdefault(new_total, selected + (ip,))
    target_bots = int(bot_counts.sum()) * target_fraction
    _, chosen_ips = min(
        ((count, ips) for count, ips in subsets.items() if ips),
        key=lambda item: (abs(item[0] - target_bots), len(item[1]), tuple(map(str, item[1]))),
    )
    held_out = df["Source IP"].isin(chosen_ips)
    return df.loc[~held_out].copy(), df.loc[held_out].copy(), list(chosen_ips), bot_counts


def _fit_random_forest(train, test, candidates):
    x_train, x_test, feature_names = _prepare_features(train, test, candidates)
    model = _call_model(_new_forest().fit, x_train, train["target"].to_numpy())
    return model, x_train, x_test, feature_names


def _fit_isolation_metrics(train_labels, x_train, x_test, test_labels):
    benign = x_train[np.asarray(train_labels) == 0]
    if not len(benign):
        raise ValueError("Isolation Forest requires BENIGN rows in its fitting split")
    model = _call_model(IsolationForest(random_state=RANDOM_STATE).fit, benign)
    prediction = _call_model(model.predict, x_test) == -1
    score = -_call_model(model.decision_function, x_test)
    return _metrics(test_labels, prediction, score)


def _print_metrics_table(rows):
    print("| model | precision | recall | F1 | average precision (PR-AUC) | tn | fp | fn | tp | FP / 1,000 BENIGN |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name, result in rows:
        print(_report_row(name, result))


def _run_extended(train, test, candidates, test_features, matches, forest, feature_names, all_rows):
    y_test = test["target"].to_numpy()

    print("\n\n=== A. Alarm-budget thresholds ===")
    fit_train, validation = time_split(train, 0.7)
    x_fit, x_validation_test, _ = _prepare_features(
        fit_train, pd.concat([validation, test], ignore_index=True), candidates)
    x_validation = x_validation_test[:len(validation)]
    x_budget_test = x_validation_test[len(validation):]
    budget_model = _call_model(_new_forest().fit, x_fit, fit_train["target"].to_numpy())
    validation_scores = _positive_probability(budget_model, x_validation)
    test_scores = _positive_probability(budget_model, x_budget_test)
    print("| BENIGN false-alarm budget / 1,000 | threshold | validation false alarms / 1,000 BENIGN | test precision | test recall | tp | fp | fn | test false alarms / 1,000 BENIGN |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for budget in (1, 5):
        threshold, validation_rate = select_alarm_threshold(
            validation["target"].to_numpy(), validation_scores, budget)
        if threshold is None:
            print(f"| {budget} | no threshold meets budget | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |")
            continue
        result = _metrics_from_scores(y_test, test_scores, threshold)
        print(f"| {budget} | {threshold:.8f} | {validation_rate:.2f} | {result['precision']:.4f} "
              f"| {result['recall']:.4f} | {result['tp']} | {result['fp']} | {result['fn']} "
              f"| {result['fp_per_1000_benign']:.2f} |")

    print("\n\n=== B. Held-out machines ===")
    machine_train, machine_test, held_out_ips, bot_counts = split_held_out_machines(all_rows)
    print("Bot flows per Source IP:")
    for ip, count in bot_counts.items():
        print(f"{ip}: {int(count)}")
    machine_y_train = machine_train["target"].to_numpy()
    machine_y_test = machine_test["target"].to_numpy()
    print(f"Held-out Source IPs: {', '.join(map(str, held_out_ips))}")
    print(f"Train: Bot {int((machine_y_train == 1).sum())}, BENIGN {int((machine_y_train == 0).sum())}")
    print(f"Test: Bot {int((machine_y_test == 1).sum())}, BENIGN {int((machine_y_test == 0).sum())}")
    if bot_counts.size < 3 or int((machine_y_test == 1).sum()) < 50:
        print("*** WARNING: fewer than 3 distinct Bot Source IPs or fewer than 50 held-out Bot flows. ***")
    machine_model, machine_x_train, machine_x_test, _ = _fit_random_forest(
        machine_train, machine_test, candidates)
    machine_prediction = _call_model(machine_model.predict, machine_x_test)
    machine_scores = _positive_probability(machine_model, machine_x_test)
    machine_rows = [("Random forest", _metrics(machine_y_test, machine_prediction, machine_scores))]
    machine_rows.append(("Isolation Forest (BENIGN-only)",
                         _fit_isolation_metrics(machine_y_train, machine_x_train,
                                                machine_x_test, machine_y_test)))
    _print_metrics_table(machine_rows)

    print("\n\n=== C. Duplicate-free test ===")
    duplicate_free = ~matches
    duplicate_y = y_test[duplicate_free]
    duplicate_features = test_features[duplicate_free]
    duplicate_prediction = _call_model(forest.predict, duplicate_features)
    duplicate_scores = _positive_probability(forest, duplicate_features)
    duplicate_result = _metrics(duplicate_y, duplicate_prediction, duplicate_scores)
    duplicate_bots = int((duplicate_y == 1).sum())
    duplicate_benign = int((duplicate_y == 0).sum())
    print(f"Remaining test rows: {len(duplicate_y)} (Bot {duplicate_bots}, BENIGN {duplicate_benign})")
    print("| model | precision | recall | tp | fp | fn | false alarms / 1,000 BENIGN |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    print(f"| Random forest | {duplicate_result['precision']:.4f} | {duplicate_result['recall']:.4f} "
          f"| {duplicate_result['tp']} | {duplicate_result['fp']} | {duplicate_result['fn']} "
          f"| {duplicate_result['fp_per_1000_benign']:.2f} |")

    print("\n\n=== D. Feature ablation ===")
    ablations = [
        ("without Init_Win_bytes_forward/backward",
         {"Init_Win_bytes_forward", "Init_Win_bytes_backward"}),
        ("without top 4 main-run features",
         {feature_names[index] for index in np.argsort(forest.feature_importances_)[-4:]}),
    ]
    ablation_rows = []
    for label, excluded in ablations:
        features = [feature for feature in candidates if feature not in excluded]
        model, _, x_test, _ = _fit_random_forest(train, test, features)
        prediction = _call_model(model.predict, x_test)
        scores = _positive_probability(model, x_test)
        ablation_rows.append((label, _metrics(y_test, prediction, scores)))
    _print_metrics_table(ablation_rows)


def split_cleaner_machine_rows(df, held_out_ips):
    """Split held-out-source rows from training rows with no held-out endpoint."""
    held_out = set(held_out_ips)
    test_mask = df["Source IP"].isin(held_out)
    train_mask = ~df["Source IP"].isin(held_out) & ~df["Destination IP"].isin(held_out)
    return df.loc[train_mask].copy(), df.loc[test_mask].copy()


def _external_bot_source_ips(df):
    private_network = ipaddress.ip_network("192.168.0.0/16")
    bot_sources = df.loc[df["target"] == 1, "Source IP"].dropna().unique()
    return sorted(
        (source for source in bot_sources
         if ipaddress.ip_address(str(source)) not in private_network),
        key=str,
    )


def _print_bot_source_counts(train):
    counts = train.loc[train["target"] == 1].groupby("Source IP", dropna=False).size()
    print("Bot flows per Source IP in train:")
    for source, count in counts.items():
        print(f"{source}: {int(count)}")


def _fit_machine_metrics(train, test, candidates):
    if train.empty or test.empty:
        raise ValueError("diagnostic machine split must have non-empty train and test rows")
    x_train, x_test, _ = _prepare_features(train, test, candidates)
    y_train, y_test = train["target"].to_numpy(), test["target"].to_numpy()
    if not len(y_train[y_train == 0]) or not len(y_test):
        raise ValueError("diagnostic machine split requires BENIGN training rows and test rows")
    model = _call_model(_new_forest(n_jobs=1).fit, x_train, y_train)
    prediction = _call_model(model.predict, x_test)
    scores = _positive_probability(model, x_test)
    rows = [("Random forest", _metrics(y_test, prediction, scores))]
    rows.append(("Isolation Forest (BENIGN-only)",
                 _fit_isolation_metrics(y_train, x_train, x_test, y_test)))
    return rows


def _print_diagnose(train, test, test_features, forest, candidates, all_rows):
    print("\n\n=== E. Per-source breakdown of main time split ===")
    test_predictions = _predict_sequentially(forest, test_features)
    bot_rows = all_rows.loc[all_rows["target"] == 1]
    bot_sources = sorted(bot_rows["Source IP"].dropna().unique(), key=str)
    train_bot_counts = train.loc[train["target"] == 1].groupby("Source IP").size()
    test_bot_counts = test.loc[test["target"] == 1].groupby("Source IP").size()
    prediction_by_source = {}
    test_results = test.loc[:, ["Source IP", "target", "ts"]].copy()
    test_results["prediction"] = test_predictions
    for source, rows in test_results.loc[test_results["target"] == 1].groupby("Source IP"):
        prediction_by_source[source] = (
            int((rows["prediction"] == 1).sum()),
            int((rows["prediction"] == 0).sum()),
        )
    print("| Source IP | Bot train | Bot test | tp | fn | first Bot timestamp | last Bot timestamp |")
    print("|---|---:|---:|---:|---:|---|---|")
    for source in bot_sources:
        source_rows = bot_rows.loc[bot_rows["Source IP"] == source, "ts"]
        tp, fn = prediction_by_source.get(source, (0, 0))
        print(f"| {source} | {int(train_bot_counts.get(source, 0))} "
              f"| {int(test_bot_counts.get(source, 0))} | {tp} | {fn} "
              f"| {source_rows.min()} | {source_rows.max()} |")

    _, _, held_out_ips, _ = split_held_out_machines(all_rows)
    candidates = [name for name in candidates if name != "Destination Port"]
    print("\n\n=== F. Cleaner machine split ===")
    cleaner_train, cleaner_test = split_cleaner_machine_rows(all_rows, held_out_ips)
    _print_cleaner_split("F", cleaner_train, cleaner_test, held_out_ips, candidates)

    print("\n\n=== G. Cleaner machine split excluding external Bot sources ===")
    external_ips = _external_bot_source_ips(all_rows)
    external_set = set(external_ips)
    cleaner_train_g = cleaner_train.loc[
        ~cleaner_train["Source IP"].isin(external_set)
        & ~cleaner_train["Destination IP"].isin(external_set)
    ].copy()
    print(f"Removed Bot Source IPs outside 192.168.0.0/16: {', '.join(map(str, external_ips)) or '(none)'}")
    _print_cleaner_split("G", cleaner_train_g, cleaner_test, held_out_ips, candidates)


def _print_cleaner_split(label, train, test, held_out_ips, candidates):
    y_train, y_test = train["target"].to_numpy(), test["target"].to_numpy()
    print(f"Held-out Source IPs: {', '.join(map(str, held_out_ips))}")
    print(f"Train: Bot {int((y_train == 1).sum())}, BENIGN {int((y_train == 0).sum())}")
    print(f"Test: Bot {int((y_test == 1).sum())}, BENIGN {int((y_test == 0).sum())}")
    if int((y_test == 1).sum()) < 50:
        print("*** WARNING: fewer than 50 Bot flows in the test part. ***")
    _print_bot_source_counts(train)
    _print_metrics_table(_fit_machine_metrics(train, test, candidates))


def run_experiment(path=DEFAULT_FILE, train_frac=0.6, extended=False, diagnose=False,
                   audit_labels=False, save_path=None):
    df, dropped_labels = load_flow_data(path)
    if df.empty or df["target"].nunique() != 2:
        raise ValueError("the retained data must contain both BENIGN and Bot flows")
    train, test = time_split(df, train_frac)
    y_train, y_test = train["target"].to_numpy(), test["target"].to_numpy()
    if set(np.unique(y_train)) != {0, 1}:
        raise ValueError("the training time split must contain both BENIGN and Bot flows")

    train_features, test_features, names = _prepare_features(
        train, test, feature_columns(df))
    matches = _matching_training_rows(train_features, test_features)

    counts = {
        "train": {label: int((y_train == value).sum()) for label, value in (("Bot", 1), ("BENIGN", 0))},
        "test": {label: int((y_test == value).sum()) for label, value in (("Bot", 1), ("BENIGN", 0))},
    }
    print(f"Rows: {len(df):,} retained; {dropped_labels:,} rows dropped for labels other than Bot/BENIGN")
    print("\n| split | Bot | BENIGN |")
    print("|---|---:|---:|")
    for split in ("train", "test"):
        print(f"| {split} | {counts[split]['Bot']:,} | {counts[split]['BENIGN']:,} |")
    if counts["test"]["Bot"] < 50:
        print(f"\n*** WARNING: only {counts['test']['Bot']} Bot flows in the test part (<50). ***")
    print("\nExact test feature vectors also present in training:")
    print(f"Bot: {int(matches[y_test == 1].sum())}; BENIGN: {int(matches[y_test == 0].sum())}")

    dummy = _call_model(DummyClassifier(strategy="stratified", random_state=RANDOM_STATE).fit,
                        train_features, y_train)
    logistic = _call_model(LogisticRegression(class_weight="balanced", max_iter=1000,
                                               random_state=RANDOM_STATE).fit,
                           train_features, y_train)
    forest = _call_model(_new_forest().fit, train_features, y_train)
    benign_train = train_features[y_train == 0]
    isolation = _call_model(IsolationForest(random_state=RANDOM_STATE).fit, benign_train)

    rows = []
    dummy_prediction = _call_model(dummy.predict, test_features)
    rows.append(("Dummy stratified", _metrics(y_test, dummy_prediction,
                                               _call_model(dummy.predict_proba, test_features)[:, list(dummy.classes_).index(1)])))
    logistic_prediction = _call_model(logistic.predict, test_features)
    rows.append(("Logistic regression", _metrics(y_test, logistic_prediction,
                                                  _call_model(logistic.predict_proba, test_features)[:, list(logistic.classes_).index(1)])))
    forest_prediction = _call_model(forest.predict, test_features)
    rows.append(("Random forest", _metrics(y_test, forest_prediction,
                                            _call_model(forest.predict_proba, test_features)[:, list(forest.classes_).index(1)])))
    isolation_prediction = _call_model(isolation.predict, test_features) == -1
    rows.append(("Isolation Forest (BENIGN-only)", _metrics(y_test, isolation_prediction,
                                                             -_call_model(isolation.decision_function, test_features))))

    sensitivity_train, sensitivity_test, sensitivity_names = _prepare_features(
        train, test, feature_columns(df, include_destination_port=True))
    sensitivity = _call_model(RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample",
                                                      n_jobs=-1, random_state=RANDOM_STATE).fit,
                              sensitivity_train, y_train)
    sensitivity_prediction = _call_model(sensitivity.predict, sensitivity_test)
    rows.append(("with Destination Port (shortcut risk)",
                 _metrics(y_test, sensitivity_prediction,
                          _call_model(sensitivity.predict_proba, sensitivity_test)[:, list(sensitivity.classes_).index(1)])))

    print("\n| model | precision | recall | F1 | average precision (PR-AUC) | tn | fp | fn | tp | FP / 1,000 BENIGN |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name, result in rows:
        print(_report_row(name, result))

    print("\nTop 10 RandomForest feature importances:")
    feature_importances = forest.feature_importances_
    importances = []
    for index in np.argsort(feature_importances)[::-1][:10]:
        importance = float(feature_importances[index])
        importances.append({"feature": names[index], "importance": round(importance, 6)})
        print(f"{names[index]}: {importance:.6f}")
    audit = None
    if audit_labels:
        audit = _audit_label_windows(df, test, forest_prediction,
                                     next(result for name, result in rows if name == "Random forest"))
    if extended:
        _run_extended(train, test, feature_columns(df), test_features, matches,
                      forest, names, df)
    if diagnose:
        _print_diagnose(train, test, test_features, forest, feature_columns(df), df)
    result = {"counts": counts, "dropped_labels": dropped_labels, "features": names,
              "sensitivity_features": sensitivity_names, "results": rows}
    if audit is not None:
        result["audit"] = audit
    if save_path:
        payload = {
            "retained_rows": len(df),
            "counts": counts,
            "exact_test_feature_vectors_in_training": {
                "Bot": int(matches[y_test == 1].sum()),
                "BENIGN": int(matches[y_test == 0].sum()),
            },
            "dropped_labels": dropped_labels,
            "results": [
                {"model": name, "metrics": {
                    "precision": round(float(metrics["precision"]), 4),
                    "recall": round(float(metrics["recall"]), 4),
                    "f1": round(float(metrics["f1"]), 4),
                    "average_precision": round(float(metrics["average_precision"]), 4),
                    "tn": metrics["tn"], "fp": metrics["fp"], "fn": metrics["fn"],
                    "tp": metrics["tp"],
                    "fp_per_1000_benign": round(float(metrics["fp_per_1000_benign"]), 2),
                }}
                for name, metrics in rows
            ],
            "top_10_feature_importances": importances,
            "seed": RANDOM_STATE,
            "train_frac": train_frac,
            "bin_width": None,
            "library_versions": {
                "python": platform.python_version(),
                "numpy": np.__version__,
                "pandas": pd.__version__,
                "scikit-learn": version("scikit-learn"),
            },
        }
        if audit is not None:
            payload["audit"] = audit
        output_path = Path(save_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return result
