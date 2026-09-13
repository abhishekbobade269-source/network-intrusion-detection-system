"""Shared types used across the rule engine, ML scorer, and alerting layer.

Kept dependency-free (no imports from sibling packages) so every layer can
import from here without risking a circular import.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class DetectorKind(StrEnum):
    SIGNATURE = "signature"
    ANOMALY = "anomaly"


@dataclass(slots=True, frozen=True)
class Finding:
    """One detector's opinion about one flow — the unit the pipeline combines
    into an `Alert` before it reaches storage/notification.
    """

    detector: DetectorKind
    rule_id: str
    name: str
    severity: Severity
    confidence: float  # 0..1
    description: str
    evidence: dict[str, float | int | str] | None = None
