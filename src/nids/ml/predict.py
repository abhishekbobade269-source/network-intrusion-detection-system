"""Live anomaly scoring: loads the joblib artifact produced by
`nids.ml.train` and scores one `FlowRecord` at a time.

Raw IsolationForest scores are converted to a stable [0, 1] "anomaly score"
using the (lo, hi) calibration bounds captured at training time, so a
single flow can be scored without needing a batch to normalize against.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from nids.common import DetectorKind, Finding, Severity
from nids.flows.flow import FlowRecord
from nids.logging_config import get_logger
from nids.ml.features import FEATURE_COLUMNS, record_to_vector

logger = get_logger(__name__)


class ModelNotLoadedError(RuntimeError):
    """Raised when scoring is attempted before a model artifact is available."""


class AnomalyScorer:
    """Wraps the trained (scaler + IsolationForest) pipeline for online use."""

    def __init__(self, model_path: str | Path, threshold: float = 0.5) -> None:
        self.model_path = Path(model_path)
        self.threshold = threshold
        self._pipeline = None
        self._feature_columns: tuple[str, ...] = FEATURE_COLUMNS
        self._calib_lo = 0.0
        self._calib_hi = 1.0
        self._metadata: dict = {}

    @property
    def is_loaded(self) -> bool:
        return self._pipeline is not None

    def load(self) -> None:
        if not self.model_path.exists():
            logger.warning("ml.model_missing", path=str(self.model_path))
            return
        artifact = joblib.load(self.model_path)
        self._pipeline = artifact["pipeline"]
        self._feature_columns = tuple(artifact.get("feature_columns", FEATURE_COLUMNS))
        calib = artifact.get("score_calibration", {"lo": 0.0, "hi": 1.0})
        self._calib_lo, self._calib_hi = float(calib["lo"]), float(calib["hi"])
        self._metadata = artifact.get("metadata", {})
        if self._feature_columns != FEATURE_COLUMNS:
            logger.error(
                "ml.feature_schema_mismatch",
                model_columns=self._feature_columns,
                current_columns=FEATURE_COLUMNS,
            )
        logger.info("ml.model_loaded", path=str(self.model_path), metadata=self._metadata)

    def score(self, record: FlowRecord) -> float:
        """Return an anomaly score in [0, 1]; 0 = looks benign, 1 = maximally anomalous."""
        if self._pipeline is None:
            raise ModelNotLoadedError("call .load() before scoring, or check .is_loaded first")

        vector = np.asarray([record_to_vector(record)], dtype=float)
        raw = self._pipeline.named_steps["model"].score_samples(
            self._pipeline.named_steps["scaler"].transform(vector)
        )[0]
        anomaly = -raw
        span = self._calib_hi - self._calib_lo
        if span < 1e-12:
            return 0.0
        return float(np.clip((anomaly - self._calib_lo) / span, 0.0, 1.0))

    def predict(self, record: FlowRecord) -> Finding | None:
        """Score a flow and return a Finding if it clears `self.threshold`."""
        if not self.is_loaded:
            return None
        score = self.score(record)
        if score < self.threshold:
            return None

        if score >= 0.9:
            severity = Severity.CRITICAL
        elif score >= 0.7:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        return Finding(
            detector=DetectorKind.ANOMALY,
            rule_id="ML_ANOMALY",
            name="Anomalous flow (ML)",
            severity=severity,
            confidence=score,
            description=(
                f"Isolation-forest anomaly score {score:.3f} for flow "
                f"{record.src_ip}:{record.src_port} -> {record.dst_ip}:{record.dst_port}"
            ),
            evidence={
                "anomaly_score": round(score, 4),
                "src_ip": record.src_ip,
                "dst_ip": record.dst_ip,
                "dst_port": record.dst_port,
            },
        )
