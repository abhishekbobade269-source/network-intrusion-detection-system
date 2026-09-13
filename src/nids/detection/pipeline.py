"""Pure, synchronous detection core: packet in, findings out.

Kept free of asyncio/DB/network so it's trivially unit-testable — feed it
packets, assert on findings. `DetectionRunner` (runner.py) is the thin async
layer that drives this from a live NIC or a pcap and persists the results.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from nids.capture.packet import Packet
from nids.common import Finding
from nids.flows.flow import FlowRecord
from nids.flows.flow_tracker import FlowTracker
from nids.logging_config import get_logger
from nids.ml.predict import AnomalyScorer
from nids.rules.engine import RuleEngine
from nids.rules.scan_detector import PortScanDetector

logger = get_logger(__name__)


@dataclass(slots=True, frozen=True)
class Detection:
    """One finding, bound to the flow that produced it — everything the
    alerting layer needs to build a storable/notifiable alert.
    """

    record: FlowRecord
    finding: Finding


class DetectionEngine:
    """Combines flow tracking, signature rules, the host-scan detector, and
    the ML anomaly scorer into a single `handle_packet` / `poll` API.
    """

    def __init__(
        self,
        rule_engine: RuleEngine,
        scan_detector: PortScanDetector | None = None,
        anomaly_scorer: AnomalyScorer | None = None,
        flow_tracker: FlowTracker | None = None,
        ml_enabled: bool = True,
    ) -> None:
        self.rule_engine = rule_engine
        self.scan_detector = scan_detector or PortScanDetector()
        self.anomaly_scorer = anomaly_scorer
        self.ml_enabled = ml_enabled and anomaly_scorer is not None
        self.flow_tracker = flow_tracker or FlowTracker()
        self.packets_seen = 0
        self.flows_evaluated = 0

    def handle_packet(self, pkt: Packet) -> list[Detection]:
        self.packets_seen += 1
        record = self.flow_tracker.update(pkt)
        if record is None:
            return []
        return self._evaluate(record)

    def poll(self, now: float | None = None) -> list[Detection]:
        """Expire idle/long-lived flows and evaluate them. Call this
        periodically (the runner does so once per batch) so flows that
        never see a FIN/RST (UDP, abandoned TCP, scans) still get scored.
        """
        now = now if now is not None else time.time()
        detections: list[Detection] = []
        for record in self.flow_tracker.poll(now):
            detections.extend(self._evaluate(record))
        return detections

    def flush(self) -> list[Detection]:
        detections: list[Detection] = []
        for record in self.flow_tracker.flush_all():
            detections.extend(self._evaluate(record))
        return detections

    def _evaluate(self, record: FlowRecord) -> list[Detection]:
        self.flows_evaluated += 1
        findings: list[Finding] = list(self.rule_engine.evaluate(record))

        scan_finding = self.scan_detector.observe(record)
        if scan_finding is not None:
            findings.append(scan_finding)

        if self.ml_enabled and self.anomaly_scorer is not None and self.anomaly_scorer.is_loaded:
            ml_finding = self.anomaly_scorer.predict(record)
            if ml_finding is not None:
                findings.append(ml_finding)

        if findings:
            logger.info(
                "detection.flow_flagged",
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                dst_port=record.dst_port,
                rule_ids=[f.rule_id for f in findings],
            )
        return [Detection(record=record, finding=f) for f in findings]
