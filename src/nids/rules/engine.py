"""Threshold rule engine: each rule is a small AND-list of conditions over a
`FlowRecord`'s fields (and its derived `to_feature_dict()`), loaded from
YAML so new signatures ship as data, not code.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from nids.common import DetectorKind, Finding, Severity
from nids.flows.flow import FlowRecord
from nids.logging_config import get_logger

logger = get_logger(__name__)

_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": operator.eq,
    "ne": operator.ne,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
    "in": lambda a, b: a in b,
}


@dataclass(slots=True, frozen=True)
class Condition:
    field: str
    op: str
    value: Any

    def matches(self, record: dict[str, Any]) -> bool:
        if self.field not in record:
            return False
        fn = _OPS.get(self.op)
        if fn is None:
            raise ValueError(f"unknown rule operator: {self.op!r}")
        try:
            return bool(fn(record[self.field], self.value))
        except TypeError:
            return False


@dataclass(slots=True, frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    description: str
    conditions: tuple[Condition, ...]
    confidence: float = 0.85

    def evaluate(self, record: dict[str, Any]) -> bool:
        return all(cond.matches(record) for cond in self.conditions)


class RuleEngine:
    """Evaluates every loaded rule against a flow's feature dict.

    Also exposes `protocol`/`dst_port`/`src_ip` etc. from the raw record for
    rules that key off identity fields rather than statistical features.
    """

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules
        logger.info("rule_engine.loaded", count=len(rules))

    def evaluate(self, record: FlowRecord) -> list[Finding]:
        context: dict[str, Any] = {
            **record.to_feature_dict(),
            "protocol": int(record.protocol),
            "dst_port": record.dst_port,
            "src_port": record.src_port,
        }
        findings: list[Finding] = []
        for rule in self.rules:
            if rule.evaluate(context):
                findings.append(
                    Finding(
                        detector=DetectorKind.SIGNATURE,
                        rule_id=rule.id,
                        name=rule.name,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        description=rule.description,
                        evidence={
                            "src_ip": record.src_ip,
                            "dst_ip": record.dst_ip,
                            "dst_port": record.dst_port,
                            "duration_s": round(record.duration_s, 3),
                            "total_packets": record.total_packets,
                        },
                    )
                )
        return findings
