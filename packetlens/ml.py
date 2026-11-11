"""Optional machine-learning detectors that plug into the same per-second bins.

Interface (so any model can be dropped in, including a pretrained time-series model):
    fit(bins)      learn what "normal" looks like from a list of bin dicts
    predict(bins)  list[bool], True where a bin is anomalous

Isolation Forest and an optional zero-shot IBM Granite forecaster implement this interface.
"""
import math

FEATURES = ("packets", "bytes", "syn", "dns", "sources")


class IsolationForestDetector:
    name = "isolation_forest"

    def __init__(self, contamination=0.01, seed=0, n_estimators=200, features=FEATURES):
        self.features = tuple(features)
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError as e:        # pragma: no cover
            raise RuntimeError("Isolation Forest needs scikit-learn: pip install scikit-learn") from e
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination,
                                     random_state=seed)

    def _matrix(self, bins):
        return [[b[f] for f in self.features] for b in bins]

    def fit(self, bins):
        self.model.fit(self._matrix(bins))
        return self

    def predict(self, bins):
        return [p == -1 for p in self.model.predict(self._matrix(bins))]


class GraniteForecastDetector:
    """Zero-shot TTM forecasts with a threshold calibrated on training residuals only."""

    name = "granite"
    MODEL_PATH = "ibm-granite/granite-timeseries-ttm-r2"
    REVISION = "90-30-ft-l1-r2.1"
    CONTEXT_LENGTH = 90
    HORIZON = 30
    FEATURE = "flows"

    def __init__(self, false_alarm_budget=1.0, forecaster=None):
        if false_alarm_budget < 0:
            raise ValueError("false-alarm budget must be non-negative")
        self.false_alarm_budget = float(false_alarm_budget)
        self._forecaster = forecaster
        self._model = None
        self.threshold = None
        self.residual_spread = None
        self.calibration_bins = 0
        self.calibration_residuals = 0
        self.calibration_hours = 0.0
        self._library_versions = None

    def _ensure_model(self):
        if self._forecaster is not None or self._model is not None:
            return
        try:
            import torch
            from tsfm_public.toolkit.get_model import get_model
        except ImportError as e:        # pragma: no cover - optional extra
            raise RuntimeError("Granite forecasting needs the granite extra: pip install '.[granite]'") from e

        model_options = {
            "model_path": self.MODEL_PATH,
            "context_length": self.CONTEXT_LENGTH,
            "prediction_length": self.HORIZON,
            "freq": "min",
            "prefer_l1_loss": True,
            "token": False,
        }
        revision = get_model(**model_options, return_model_key=True)
        if revision != self.REVISION:
            raise RuntimeError(f"Granite selected revision {revision!r}; expected {self.REVISION!r}")
        model = get_model(**model_options)
        if (model.config.context_length != self.CONTEXT_LENGTH
                or model.config.prediction_length != self.HORIZON):
            raise RuntimeError("Granite model context or horizon does not match the configured revision")
        model.eval()
        self._model = model
        from importlib.metadata import version
        self._library_versions = {
            name: version(name) for name in ("granite-tsfm", "torch", "transformers")
        }

        def forecast(context):
            values = torch.tensor(context, dtype=torch.float32).reshape(1, self.CONTEXT_LENGTH, 1)
            frequency = torch.tensor([1], dtype=torch.int)
            with torch.inference_mode():
                output = model(past_values=values, freq_token=frequency)
            return float(output.prediction_outputs[0, 0, 0].item())

        self._forecaster = forecast

    def _value(self, bin_record):
        try:
            value = float(bin_record[self.FEATURE])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Granite bins must contain a numeric {self.FEATURE!r} field") from e
        if not math.isfinite(value):
            raise ValueError(f"Granite bin {self.FEATURE!r} values must be finite")
        return value

    def _rolling_residuals(self, bins, history=None):
        values = [self._value(b) for b in bins]
        prior = [self._value(b) for b in history] if history is not None else []
        prior = prior[-self.CONTEXT_LENGTH:]
        residuals = []
        for actual in values:
            if len(prior) < self.CONTEXT_LENGTH:
                residuals.append(None)
            else:
                forecast = float(self._forecaster(prior[-self.CONTEXT_LENGTH:]))
                residuals.append(abs(actual - forecast))
            prior.append(actual)
        return residuals

    def fit(self, bins):
        self._ensure_model()
        residuals = [value for value in self._rolling_residuals(bins) if value is not None]
        if not residuals:
            raise ValueError(f"Granite needs more than {self.CONTEXT_LENGTH} training bins to calibrate")

        mean = sum(residuals) / len(residuals)
        spread = math.sqrt(sum((value - mean) ** 2 for value in residuals) / len(residuals))
        self.residual_spread = spread if spread > 0 else max(abs(mean), 1.0)
        scores = sorted(value / self.residual_spread for value in residuals)
        self.calibration_hours = len(residuals) / 60
        allowed = min(math.floor(self.false_alarm_budget * self.calibration_hours), len(scores))
        self.threshold = (scores[0] - 1e-12 if allowed == len(scores)
                          else scores[len(scores) - allowed - 1])
        self.calibration_bins = len(bins)
        self.calibration_residuals = len(residuals)
        return self

    def predict(self, bins, history=None):
        if self.threshold is None:
            raise RuntimeError("Granite detector must be fitted before predict")
        self._ensure_model()
        residuals = self._rolling_residuals(bins, history)
        return [bool(value is not None and value / self.residual_spread > self.threshold)
                for value in residuals]

    @property
    def metadata(self):
        return {
            "revision": self.REVISION,
            "context_length": self.CONTEXT_LENGTH,
            "horizon": self.HORIZON,
            "feature": self.FEATURE,
            "false_alarm_budget_per_hour": self.false_alarm_budget,
            "threshold": self.threshold,
            "residual_spread": self.residual_spread,
            "calibration_bins": self.calibration_bins,
            "calibration_residuals": self.calibration_residuals,
            "calibration_hours": self.calibration_hours,
            "library_versions": self._library_versions,
        }
