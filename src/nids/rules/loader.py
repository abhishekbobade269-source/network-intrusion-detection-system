"""Loads and validates YAML rule definitions into `Rule` objects.

Rule file schema (one list per file, any number of files in the rules dir):

    - id: PORT_SCAN_SYN_ONLY
      name: TCP SYN-only flow (possible scan probe)
      severity: medium
      confidence: 0.7
      description: >
        Flow consists almost entirely of SYNs with no matching ACK/FIN —
        typical of a half-open (stealth) port-scan probe.
      conditions:
        - field: syn_count
          op: gte
          value: 1
        - field: ack_count
          op: eq
          value: 0
        - field: total_packets
          op: lte
          value: 3
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from nids.common import Severity
from nids.logging_config import get_logger
from nids.rules.engine import Condition, Rule

logger = get_logger(__name__)


class _ConditionModel(BaseModel):
    field: str
    op: str
    value: Any


class _RuleModel(BaseModel):
    id: str
    name: str
    severity: Severity
    description: str
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    conditions: list[_ConditionModel]


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """Load and validate every *.yaml/*.yml file in `rules_dir`.

    A malformed file is logged and skipped rather than crashing the whole
    engine — one bad signature shouldn't take detection offline.
    """
    rules_dir = Path(rules_dir)
    rules: list[Rule] = []
    seen_ids: set[str] = set()

    if not rules_dir.exists():
        logger.warning("rules.dir_missing", path=str(rules_dir))
        return rules

    for path in sorted((*rules_dir.glob("*.yaml"), *rules_dir.glob("*.yml"))):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            if not isinstance(raw, list):
                raise ValueError("rule file must contain a YAML list of rules")
            for entry in raw:
                model = _RuleModel.model_validate(entry)
                if model.id in seen_ids:
                    logger.warning("rules.duplicate_id", id=model.id, file=str(path))
                    continue
                seen_ids.add(model.id)
                rules.append(
                    Rule(
                        id=model.id,
                        name=model.name,
                        severity=model.severity,
                        description=model.description,
                        confidence=model.confidence,
                        conditions=tuple(
                            Condition(field=c.field, op=c.op, value=c.value)
                            for c in model.conditions
                        ),
                    )
                )
        except (yaml.YAMLError, ValidationError, ValueError, OSError) as exc:
            logger.error("rules.load_failed", file=str(path), error=str(exc))
            continue

    logger.info("rules.loaded", count=len(rules), dir=str(rules_dir))
    return rules
