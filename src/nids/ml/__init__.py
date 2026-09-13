"""ML anomaly-detection layer: unsupervised scoring of flows that the
signature engine doesn't already recognize — the "catch what we didn't
write a rule for" half of the hybrid design.
"""

from nids.ml.features import FEATURE_COLUMNS, feature_dict_to_vector, record_to_vector
from nids.ml.predict import AnomalyScorer

__all__ = ["FEATURE_COLUMNS", "AnomalyScorer", "feature_dict_to_vector", "record_to_vector"]
