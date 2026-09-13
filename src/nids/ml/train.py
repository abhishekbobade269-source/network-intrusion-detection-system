"""Trains the unsupervised anomaly-detection model.

Design choice: the signature engine (`nids.rules`) already covers *known*
attack shapes, so the ML side's job is to catch what the rules don't —
that means training an anomaly detector (Isolation Forest) on **benign
traffic only**, not a supervised classifier on attack labels. A held-out
mixed (benign + attack) split is still used purely for evaluation, since
CICIDS2017/synthetic data happen to carry labels we can check ourselves
against.

Usage:
    python -m nids.ml.train --dataset synthetic --out models/anomaly_model.joblib
    python -m nids.ml.train --dataset cicids2017 \
        --cicids-csv data/raw/Monday.csv --cicids-csv data/raw/Tuesday.csv
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import joblib
import numpy as np
import typer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from nids.logging_config import configure_logging, get_logger
from nids.ml.datasets import load_cicids2017, make_synthetic_dataset
from nids.ml.features import FEATURE_COLUMNS

app = typer.Typer(add_completion=False, help="Train the NIDS anomaly-detection model.")
logger = get_logger(__name__)


def _isolation_forest_to_unit_score(raw_scores: np.ndarray) -> np.ndarray:
    """IsolationForest.score_samples is higher = more normal, roughly in
    [-0.5, 0.5]. Flip and min-max squash to [0, 1] so downstream code has one
    consistent "higher = more anomalous" convention regardless of model type.
    """
    anomaly = -raw_scores
    lo, hi = anomaly.min(), anomaly.max()
    if hi - lo < 1e-12:
        return np.zeros_like(anomaly)
    return (anomaly - lo) / (hi - lo)


@app.command()
def train(
    dataset: Annotated[str, typer.Option(help="synthetic | cicids2017")] = "synthetic",
    cicids_csv: Annotated[
        list[Path],
        typer.Option(help="CICIDS2017 CSV path(s); repeat flag for multiple daily files."),
    ] = [],  # noqa: B006 — typer re-parses this per-invocation, it's never mutated in place
    out: Annotated[Path, typer.Option()] = Path("models/anomaly_model.joblib"),
    contamination: Annotated[
        float, typer.Option(help="Expected fraction of outliers in the *training* (benign) set.")
    ] = 0.02,
    n_estimators: Annotated[int, typer.Option()] = 200,
    test_size: Annotated[float, typer.Option()] = 0.25,
    seed: Annotated[int, typer.Option()] = 42,
) -> None:
    configure_logging()

    if dataset == "synthetic":
        df = make_synthetic_dataset(seed=seed)
    elif dataset == "cicids2017":
        if not cicids_csv:
            raise typer.BadParameter("--cicids-csv is required when --dataset cicids2017")
        df = load_cicids2017(cicids_csv)
    else:
        raise typer.BadParameter(f"unknown dataset: {dataset!r}")

    logger.info(
        "train.dataset_loaded",
        dataset=dataset,
        rows=len(df),
        attack_rate=df["label"].mean(),
    )

    X = df[list(FEATURE_COLUMNS)].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)

    X_train_all, X_test, y_train_all, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y
    )
    # Train only on the benign portion of the training split — this is what
    # makes it anomaly detection rather than supervised classification.
    X_train_benign = X_train_all[y_train_all == 0]
    logger.info(
        "train.split",
        train_benign=len(X_train_benign),
        test_total=len(X_test),
        test_attack=int(y_test.sum()),
    )

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=n_estimators,
                    contamination=contamination,
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    pipeline.fit(X_train_benign)

    # Calibrate the raw score -> [0,1] anomaly-score mapping from the
    # *training* (benign) distribution, not the test set, so live scoring
    # (nids.ml.predict) can reuse these fixed bounds on one flow at a time
    # instead of needing a batch to min-max against.
    raw_train_scores = pipeline.named_steps["model"].score_samples(
        pipeline.named_steps["scaler"].transform(X_train_benign)
    )
    calib_lo = float((-raw_train_scores).min())
    calib_hi = float(np.percentile(-raw_train_scores, 99.5))  # robust to a few extreme outliers

    raw_test_scores = pipeline.named_steps["model"].score_samples(
        pipeline.named_steps["scaler"].transform(X_test)
    )
    unit_scores = _isolation_forest_to_unit_score(raw_test_scores)
    y_pred = (unit_scores >= 0.5).astype(int)

    metrics = {
        "roc_auc": float(roc_auc_score(y_test, unit_scores)) if y_test.sum() else None,
        "average_precision": float(average_precision_score(y_test, unit_scores))
        if y_test.sum()
        else None,
        "report_at_0.5": classification_report(y_test, y_pred, output_dict=True, zero_division=0),
    }
    logger.info("train.evaluation", roc_auc=metrics["roc_auc"], ap=metrics["average_precision"])

    out.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pipeline": pipeline,
        "feature_columns": list(FEATURE_COLUMNS),
        "score_calibration": {"lo": calib_lo, "hi": calib_hi},
        "metadata": {
            "trained_at": datetime.now(UTC).isoformat(),
            "dataset": dataset,
            "n_train_benign": int(len(X_train_benign)),
            "n_test": int(len(X_test)),
            "contamination": contamination,
            "n_estimators": n_estimators,
            "metrics": metrics,
        },
    }
    joblib.dump(artifact, out)
    (out.parent / f"{out.stem}.metrics.json").write_text(
        json.dumps(artifact["metadata"], indent=2, default=str), encoding="utf-8"
    )
    logger.info("train.saved", path=str(out))
    typer.echo(f"Saved model to {out}")
    typer.echo(json.dumps(metrics, indent=2, default=str))


if __name__ == "__main__":
    app()
