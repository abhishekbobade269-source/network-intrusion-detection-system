"""The single source of truth for the ML feature schema.

Both training (`nids.ml.train`) and live scoring (`nids.ml.predict`) must
use this exact column order — a mismatch here silently produces garbage
predictions, so nothing else in the codebase should hardcode this list.
Must stay in sync with `FlowRecord.to_feature_dict()`.
"""

from __future__ import annotations

from nids.flows.flow import FlowRecord

FEATURE_COLUMNS: tuple[str, ...] = (
    "duration_s",
    "total_packets",
    "total_bytes",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "fwd_pkt_len_min",
    "fwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "bwd_pkt_len_min",
    "bwd_pkt_len_max",
    "iat_mean",
    "iat_std",
    "bytes_per_s",
    "packets_per_s",
    "down_up_ratio",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
)


def feature_dict_to_vector(features: dict[str, float]) -> list[float]:
    """Project a feature dict onto FEATURE_COLUMNS order, defaulting missing keys to 0.0."""
    return [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]


def record_to_vector(record: FlowRecord) -> list[float]:
    return feature_dict_to_vector(record.to_feature_dict())
