"""Tests `load_cicids2017` against small, hand-built CSVs shaped like the
real CICFlowMeter output (including its known quirks: inconsistent header
whitespace, occasional inf values in the rate columns) — the real
multi-GB dataset is deliberately not bundled (see docs/model_card.md), so
this is what actually exercises the loader's parsing/cleaning logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nids.ml.datasets import CICIDS2017_COLUMN_MAP, load_cicids2017
from nids.ml.features import FEATURE_COLUMNS

_HEADER = ",".join(CICIDS2017_COLUMN_MAP.keys())


def _row(*, label: str, **overrides: str) -> str:
    """Build one CSV row in CICIDS2017_COLUMN_MAP's exact column order,
    defaulting every column to "10" and `Label` to `label` — pass e.g.
    `**{"Flow Bytes/s": "Infinity"}` to override a specific column by its
    real CICFlowMeter name.
    """
    row = dict.fromkeys(CICIDS2017_COLUMN_MAP, "10")
    row["Label"] = label
    row.update(overrides)
    return ",".join(row[name] for name in CICIDS2017_COLUMN_MAP)


def test_loads_and_maps_columns_and_binarizes_label(tmp_path: Path) -> None:
    csv_path = tmp_path / "Monday.csv"
    csv_path.write_text(
        "\n".join(
            [
                _HEADER,
                _row(label="BENIGN"),
                _row(label="DDoS"),
                _row(label="PortScan"),
            ]
        ),
        encoding="utf-8",
    )

    df = load_cicids2017([csv_path])

    for col in (*FEATURE_COLUMNS, "label", "label_detail"):
        assert col in df.columns
    assert list(df["label"]) == [0, 1, 1]
    assert list(df["label_detail"]) == ["BENIGN", "DDoS", "PortScan"]


def test_header_whitespace_is_stripped(tmp_path: Path) -> None:
    csv_path = tmp_path / "whitespace.csv"
    padded_header = ",".join(f" {name} " for name in CICIDS2017_COLUMN_MAP)
    csv_path.write_text(f"{padded_header}\n{_row(label='BENIGN')}", encoding="utf-8")

    df = load_cicids2017([csv_path])

    assert len(df) == 1
    assert df.iloc[0]["label"] == 0


def test_rows_with_inf_or_nan_features_are_dropped(tmp_path: Path) -> None:
    csv_path = tmp_path / "infs.csv"
    csv_path.write_text(
        "\n".join(
            [
                _HEADER,
                # "Infinity" mirrors a real CICFlowMeter quirk: Flow Bytes/s
                # and Flow Packets/s come out as inf when Flow Duration is 0.
                _row(label="BENIGN", **{"Flow Bytes/s": "Infinity"}),
                _row(label="BENIGN", **{"Flow Bytes/s": "500.0"}),
            ]
        ),
        encoding="utf-8",
    )

    df = load_cicids2017([csv_path])

    assert len(df) == 1
    assert df.iloc[0]["bytes_per_s"] == 500.0


def test_multiple_csvs_are_concatenated(tmp_path: Path) -> None:
    monday = tmp_path / "Monday.csv"
    tuesday = tmp_path / "Tuesday.csv"
    monday.write_text(f"{_HEADER}\n{_row(label='BENIGN')}", encoding="utf-8")
    tuesday.write_text(f"{_HEADER}\n{_row(label='Bot')}\n{_row(label='BENIGN')}", encoding="utf-8")

    df = load_cicids2017([monday, tuesday])

    assert len(df) == 3
    assert df["label"].tolist().count(1) == 1


def test_missing_csv_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_cicids2017([tmp_path / "does_not_exist.csv"])


def test_missing_expected_column_raises_value_error(tmp_path: Path) -> None:
    csv_path = tmp_path / "incomplete.csv"
    csv_path.write_text("Flow Duration,Label\n1000,BENIGN\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing expected columns"):
        load_cicids2017([csv_path])
