"""Signature-based detection: YAML-defined threshold rules over flow
features, plus a stateful host-scan detector for cross-flow patterns that a
single flow's fields can't express.
"""

from nids.rules.engine import Rule, RuleEngine
from nids.rules.loader import load_rules
from nids.rules.scan_detector import PortScanDetector

__all__ = ["PortScanDetector", "Rule", "RuleEngine", "load_rules"]
