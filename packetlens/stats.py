"""Standard-library block bootstrap intervals for binary detection metrics."""
import math
import random


MIN_SAMPLE_BINS = 30
DEFAULT_BOOTSTRAP_SEED = 42


def _bin_values(values):
    if isinstance(values, (list, tuple)):
        return tuple(_binary(value) for value in values)
    return (_binary(values),)


def _binary(value):
    if value is True or value == 1:
        return True
    if value is False or value == 0:
        return False
    raise ValueError("truth and prediction values must be boolean or 0/1")


def _bin_confusion(truth, prediction):
    tp = fp = fn = 0
    for actual, predicted in zip(truth, prediction):
        if actual and predicted:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1
    return tp, fp, fn


def _metrics(tp, fp, fn, bin_count, bin_seconds):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_alarms_per_hour = fp * 3600 / (bin_count * bin_seconds)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_alarms_per_hour": false_alarms_per_hour,
    }


def _percentile(sorted_values, fraction):
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (position - lower)


def block_bootstrap(truth, prediction, *, block_length=5, bin_seconds=60,
                    resamples=1000, seed=DEFAULT_BOOTSTRAP_SEED):
    """Return 95% percentile intervals over circular, contiguous time blocks.

    Each outer sequence item is one time bin. A bin may hold a boolean pair or a
    list/tuple of row labels and predictions (for per-flow rows grouped by minute).
    Returns ``(None, note)`` for empty or fewer-than-30-bin samples.
    """
    if len(truth) != len(prediction):
        raise ValueError("truth and prediction must contain the same number of bins")
    if type(block_length) is not int or block_length < 1:
        raise ValueError("block_length must be a positive integer")
    if type(resamples) is not int or resamples < 1:
        raise ValueError("resamples must be a positive integer")
    if isinstance(bin_seconds, bool) or not isinstance(bin_seconds, (int, float)):
        raise ValueError("bin_seconds must be positive and finite")
    if not math.isfinite(bin_seconds) or bin_seconds <= 0:
        raise ValueError("bin_seconds must be positive and finite")

    truth_bins = [_bin_values(values) for values in truth]
    prediction_bins = [_bin_values(values) for values in prediction]
    if any(len(actual) != len(predicted)
           for actual, predicted in zip(truth_bins, prediction_bins)):
        raise ValueError("each truth bin must align with its prediction bin")

    bin_count = len(truth_bins)
    if bin_count == 0:
        return None, "empty sample"
    if bin_count < MIN_SAMPLE_BINS:
        return None, "too few to trust"

    per_bin = [_bin_confusion(actual, predicted)
               for actual, predicted in zip(truth_bins, prediction_bins)]
    point_counts = tuple(sum(counts[index] for counts in per_bin) for index in range(3))
    point = _metrics(*point_counts, bin_count, bin_seconds)
    rng = random.Random(seed)
    replicates = {name: [] for name in point}
    starts_per_sample = math.ceil(bin_count / block_length)
    for _ in range(resamples):
        sampled = []
        for _ in range(starts_per_sample):
            start = rng.randrange(bin_count)
            sampled.extend((start + offset) % bin_count
                           for offset in range(block_length))
        sampled = sampled[:bin_count]
        counts = tuple(sum(per_bin[index][metric] for index in sampled)
                       for metric in range(3))
        sample_metrics = _metrics(*counts, bin_count, bin_seconds)
        for name, value in sample_metrics.items():
            replicates[name].append(value)

    intervals = {
        name: [_percentile(sorted(values), 0.025), _percentile(sorted(values), 0.975)]
        for name, values in replicates.items()
    }
    return {"point": point, "ci95": intervals, "n": bin_count}, None
