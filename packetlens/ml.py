"""Optional machine-learning detectors that plug into the same per-second bins.

Interface (so any model can be dropped in, including a pretrained time-series model):
    fit(bins)      learn what "normal" looks like from a list of bin dicts
    predict(bins)  list[bool], True where a bin is anomalous

Only Isolation Forest is included, as the baseline to beat. A forecasting model such as
IBM Granite Time Series would implement the same two methods: forecast the next window
and flag bins whose actual value is far from the forecast.
"""
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
