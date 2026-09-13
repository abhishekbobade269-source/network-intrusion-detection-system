"""Dataset loaders that map external, differently-named feature sets onto
`FEATURE_COLUMNS`, plus a synthetic generator so the whole training/scoring
pipeline is runnable and testable with zero external downloads.

CICIDS2017 (Sharafaldin et al., 2018) ships CICFlowMeter-generated CSVs
whose column names are a near-1:1 superset of our own flow features (we
deliberately scoped FEATURE_COLUMNS to the subset that lines up), which is
why it's the primary supported public dataset here. NSL-KDD uses a very
different connection-record schema (service/flag/src_bytes/...) and is not
column-mapped by this loader — see docs/model_card.md for how to adapt it
if you want it too.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import numpy as np
import pandas as pd

from nids.ml.features import FEATURE_COLUMNS

# CICFlowMeter column name -> our FEATURE_COLUMNS name.
# CICIDS2017 CSVs are known to ship inconsistent leading/trailing whitespace
# in headers across the 8 daily files — callers should `.str.strip()` first.
CICIDS2017_COLUMN_MAP: dict[str, str] = {
    "Flow Duration": "duration_s",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Flow IAT Mean": "iat_mean",
    "Flow IAT Std": "iat_std",
    "Flow Bytes/s": "bytes_per_s",
    "Flow Packets/s": "packets_per_s",
    "Down/Up Ratio": "down_up_ratio",
    "SYN Flag Count": "syn_count",
    "ACK Flag Count": "ack_count",
    "FIN Flag Count": "fin_count",
    "RST Flag Count": "rst_count",
    "PSH Flag Count": "psh_count",
    "URG Flag Count": "urg_count",
    "Label": "label",
}


def load_cicids2017(csv_paths: Sequence[str | Path]) -> pd.DataFrame:
    """Load one or more CICIDS2017 daily CSVs, mapped onto FEATURE_COLUMNS + 'label'.

    `label` is normalized to a binary int: 0 = BENIGN, 1 = any attack class.
    The original fine-grained label string is kept as `label_detail`.
    """
    frames: list[pd.DataFrame] = []
    for path in csv_paths:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(
                f"CICIDS2017 CSV not found: {path}. Download from "
                "https://www.unb.ca/cic/datasets/ids-2017.html and pass the "
                "local path — this loader does not fetch it for you."
            )
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        missing = [c for c in CICIDS2017_COLUMN_MAP if c not in df.columns]
        if missing:
            raise ValueError(f"{path.name} is missing expected columns: {missing}")
        mapped = df[list(CICIDS2017_COLUMN_MAP)].rename(columns=CICIDS2017_COLUMN_MAP)
        mapped["label_detail"] = mapped["label"]
        mapped["label"] = (mapped["label"].astype(str).str.upper() != "BENIGN").astype(int)
        frames.append(mapped)

    combined = pd.concat(frames, ignore_index=True)
    return _clean(combined)


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf (common in Flow Bytes/s and Flow Packets/s when duration=0)
    and drop rows with NaNs in any feature column.
    """
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=list(FEATURE_COLUMNS))
    return df.reset_index(drop=True)


def make_synthetic_dataset(
    n_benign: int = 4000,
    n_attack: int = 400,
    seed: int = 42,
) -> pd.DataFrame:
    """Generate a synthetic flow-feature dataset with a benign cluster and a
    handful of attack-shaped clusters (scan-like, flood-like, exfil-like).

    Exists purely so `make train` / CI / a fresh clone can exercise the full
    training -> scoring pipeline end to end without any external dataset —
    it is NOT a substitute for training on CICIDS2017 before relying on
    real-world detection accuracy (see docs/model_card.md).
    """
    rng = np.random.default_rng(seed)
    n_cols = len(FEATURE_COLUMNS)

    def _clip_nonneg(arr: np.ndarray) -> np.ndarray:
        return np.clip(arr, 0, None)

    benign = pd.DataFrame(
        _clip_nonneg(rng.normal(loc=1.0, scale=0.4, size=(n_benign, n_cols))),
        columns=list(FEATURE_COLUMNS),
    )
    benign["duration_s"] = _clip_nonneg(rng.normal(2.0, 1.0, n_benign))
    benign["total_packets"] = _clip_nonneg(rng.normal(20, 8, n_benign))
    benign["syn_count"] = rng.integers(0, 2, n_benign)
    benign["ack_count"] = rng.integers(1, 10, n_benign)
    benign["fin_count"] = rng.integers(0, 2, n_benign)
    benign["rst_count"] = 0
    benign["label"] = 0

    n_each = max(1, n_attack // 3)

    scan_like = pd.DataFrame(
        _clip_nonneg(rng.normal(loc=0.2, scale=0.1, size=(n_each, n_cols))),
        columns=list(FEATURE_COLUMNS),
    )
    scan_like["duration_s"] = rng.uniform(0.0001, 0.01, n_each)
    scan_like["total_packets"] = rng.integers(1, 3, n_each)
    scan_like["syn_count"] = 1
    scan_like["ack_count"] = 0
    scan_like["packets_per_s"] = rng.uniform(500, 5000, n_each)
    scan_like["label"] = 1

    flood_like = pd.DataFrame(
        _clip_nonneg(rng.normal(loc=0.3, scale=0.1, size=(n_each, n_cols))),
        columns=list(FEATURE_COLUMNS),
    )
    flood_like["total_packets"] = rng.integers(500, 5000, n_each)
    flood_like["packets_per_s"] = rng.uniform(1000, 20000, n_each)
    flood_like["syn_count"] = rng.integers(200, 2000, n_each)
    flood_like["ack_count"] = rng.integers(0, 2, n_each)
    flood_like["label"] = 1

    exfil_like = pd.DataFrame(
        _clip_nonneg(rng.normal(loc=0.5, scale=0.2, size=(n_attack - 2 * n_each, n_cols))),
        columns=list(FEATURE_COLUMNS),
    )
    exfil_like["fwd_bytes"] = rng.uniform(5_000_000, 50_000_000, len(exfil_like))
    exfil_like["down_up_ratio"] = rng.uniform(0.0, 0.01, len(exfil_like))
    exfil_like["duration_s"] = rng.uniform(5, 120, len(exfil_like))
    exfil_like["label"] = 1

    combined = pd.concat([benign, scan_like, flood_like, exfil_like], ignore_index=True)
    combined = combined.sample(frac=1, random_state=seed).reset_index(drop=True)
    return _clean(combined)
