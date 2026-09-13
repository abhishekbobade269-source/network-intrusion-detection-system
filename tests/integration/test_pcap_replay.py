"""End-to-end test: replays the committed demo pcap (see
scripts/generate_demo_pcap.py) through the real DetectionRunner and checks
that the expected attack-shaped flows are flagged and the one benign
handshake flow's *signature* findings stay empty.

Doesn't require a database — DetectionRunner/DetectionEngine are pure
capture -> detection, no persistence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nids.detection.pipeline import Detection, DetectionEngine
from nids.detection.runner import DetectionRunner
from nids.flows.flow_tracker import FlowTracker
from nids.rules.engine import RuleEngine
from nids.rules.loader import load_rules
from nids.rules.scan_detector import PortScanDetector

FIXTURE = Path(__file__).parents[1] / "fixtures" / "demo_traffic.pcap"
RULES_DIR = Path(__file__).parents[2] / "src" / "nids" / "rules" / "definitions"


@pytest.mark.asyncio
async def test_replay_flags_scan_and_flood_but_not_the_handshake() -> None:
    if not FIXTURE.exists():
        pytest.skip(f"demo fixture missing — run scripts/generate_demo_pcap.py ({FIXTURE})")

    engine = DetectionEngine(
        rule_engine=RuleEngine(load_rules(RULES_DIR)),
        scan_detector=PortScanDetector(),
        anomaly_scorer=None,  # isolate signature-engine behavior from the ML model
        flow_tracker=FlowTracker(),
        ml_enabled=False,
    )

    detections: list[Detection] = []

    async def _collect(detection: Detection) -> None:
        detections.append(detection)

    runner = DetectionRunner(engine, on_detection=_collect, poll_interval_s=1.0)
    await runner.run_pcap(str(FIXTURE))

    assert engine.packets_seen == 90

    rule_ids = {d.finding.rule_id for d in detections}
    assert "TCP_NULL_SCAN" in rule_ids
    assert "HOST_PORT_SCAN" in rule_ids
    assert "ICMP_FLOOD" in rule_ids

    handshake_findings = [d for d in detections if d.record.dst_port == 443]
    assert handshake_findings == []
