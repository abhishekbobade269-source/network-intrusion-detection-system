"""Pydantic API schemas for alerts — kept separate from the ORM model so the
wire format can evolve independently of the storage schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from nids.common import DetectorKind, Finding, Severity


class AlertCreate(BaseModel):
    detector: DetectorKind
    rule_id: str
    name: str
    severity: Severity
    confidence: float
    description: str
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    evidence: dict = {}

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
    ) -> AlertCreate:
        return cls(
            detector=finding.detector,
            rule_id=finding.rule_id,
            name=finding.name,
            severity=finding.severity,
            confidence=finding.confidence,
            description=finding.description,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            evidence=dict(finding.evidence or {}),
        )


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    detector: str
    rule_id: str
    name: str
    severity: str
    confidence: float
    description: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    evidence: dict
    acknowledged: bool


class AlertStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_detector: dict[str, int]
    top_src_ips: list[tuple[str, int]]
