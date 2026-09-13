from pathlib import Path
from unittest.mock import patch

import pytest

from nids.common import DetectorKind, Severity
from nids.flows.flow import FlowRecord
from nids.ml.datasets import make_synthetic_dataset
from nids.ml.features import FEATURE_COLUMNS, feature_dict_to_vector
from nids.ml.predict import AnomalyScorer, ModelNotLoadedError
from nids.ml.train import train


def _flow_record_from_row(row: dict) -> FlowRecord:
    return FlowRecord(
        key=("10.0.0.1", "10.0.0.2", 1, 2, 6),
        protocol=6,  # type: ignore[arg-type]
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1,
        dst_port=2,
        first_seen=0.0,
        last_seen=row["duration_s"],
        duration_s=row["duration_s"],
        total_packets=int(row["total_packets"]),
        total_bytes=int(row["total_bytes"]),
        fwd_packets=int(row["fwd_packets"]),
        bwd_packets=int(row["bwd_packets"]),
        fwd_bytes=int(row["fwd_bytes"]),
        bwd_bytes=int(row["bwd_bytes"]),
        fwd_pkt_len_mean=row["fwd_pkt_len_mean"],
        fwd_pkt_len_std=row["fwd_pkt_len_std"],
        fwd_pkt_len_min=row["fwd_pkt_len_min"],
        fwd_pkt_len_max=row["fwd_pkt_len_max"],
        bwd_pkt_len_mean=row["bwd_pkt_len_mean"],
        bwd_pkt_len_std=row["bwd_pkt_len_std"],
        bwd_pkt_len_min=row["bwd_pkt_len_min"],
        bwd_pkt_len_max=row["bwd_pkt_len_max"],
        iat_mean=row["iat_mean"],
        iat_std=row["iat_std"],
        bytes_per_s=row["bytes_per_s"],
        packets_per_s=row["packets_per_s"],
        down_up_ratio=row["down_up_ratio"],
        syn_count=int(row["syn_count"]),
        ack_count=int(row["ack_count"]),
        fin_count=int(row["fin_count"]),
        rst_count=int(row["rst_count"]),
        psh_count=int(row["psh_count"]),
        urg_count=int(row["urg_count"]),
    )


def test_synthetic_dataset_has_expected_shape() -> None:
    df = make_synthetic_dataset(n_benign=200, n_attack=40, seed=1)
    for col in (*FEATURE_COLUMNS, "label"):
        assert col in df.columns
    assert df["label"].isin([0, 1]).all()
    assert 0 < df["label"].mean() < 1


def test_feature_dict_to_vector_preserves_column_order() -> None:
    features = {col: float(i) for i, col in enumerate(FEATURE_COLUMNS)}
    vector = feature_dict_to_vector(features)
    assert vector == [float(i) for i in range(len(FEATURE_COLUMNS))]


def test_train_and_score_round_trip(tmp_path: Path) -> None:
    model_path = tmp_path / "model.joblib"

    train(
        dataset="synthetic",
        cicids_csv=[],
        out=model_path,
        contamination=0.05,
        n_estimators=25,
        test_size=0.3,
        seed=7,
    )
    assert model_path.exists()

    scorer = AnomalyScorer(model_path, threshold=0.5)
    scorer.load()
    assert scorer.is_loaded

    df = make_synthetic_dataset(n_benign=50, n_attack=20, seed=99)
    benign_row = df[df["label"] == 0].iloc[0].to_dict()
    attack_row = df[df["label"] == 1].iloc[0].to_dict()

    benign_score = scorer.score(_flow_record_from_row(benign_row))
    attack_score = scorer.score(_flow_record_from_row(attack_row))

    assert 0.0 <= benign_score <= 1.0
    assert 0.0 <= attack_score <= 1.0


def _dummy_record() -> FlowRecord:
    return _flow_record_from_row(
        dict.fromkeys(FEATURE_COLUMNS, 0.0) | {"total_packets": 1, "total_bytes": 60}
    )


def test_score_raises_before_load() -> None:
    scorer = AnomalyScorer("does/not/matter.joblib")
    with pytest.raises(ModelNotLoadedError):
        scorer.score(_dummy_record())


def test_load_missing_model_path_leaves_scorer_unloaded(tmp_path: Path) -> None:
    scorer = AnomalyScorer(tmp_path / "missing.joblib")
    scorer.load()
    assert not scorer.is_loaded


def test_predict_returns_none_when_not_loaded() -> None:
    scorer = AnomalyScorer("does/not/matter.joblib")
    assert scorer.predict(_dummy_record()) is None


def test_predict_returns_none_below_threshold(tmp_path: Path) -> None:
    model_path = tmp_path / "model.joblib"
    train(dataset="synthetic", cicids_csv=[], out=model_path, n_estimators=10, seed=1)
    scorer = AnomalyScorer(model_path, threshold=0.5)
    scorer.load()

    with patch.object(scorer, "score", return_value=0.2):
        assert scorer.predict(_dummy_record()) is None


@pytest.mark.parametrize(
    ("score", "expected_severity"),
    [(0.55, Severity.MEDIUM), (0.75, Severity.HIGH), (0.95, Severity.CRITICAL)],
)
def test_predict_maps_score_to_severity(
    tmp_path: Path, score: float, expected_severity: Severity
) -> None:
    model_path = tmp_path / "model.joblib"
    train(dataset="synthetic", cicids_csv=[], out=model_path, n_estimators=10, seed=1)
    scorer = AnomalyScorer(model_path, threshold=0.5)
    scorer.load()

    with patch.object(scorer, "score", return_value=score):
        finding = scorer.predict(_dummy_record())

    assert finding is not None
    assert finding.detector == DetectorKind.ANOMALY
    assert finding.rule_id == "ML_ANOMALY"
    assert finding.severity == expected_severity
    assert finding.confidence == score
