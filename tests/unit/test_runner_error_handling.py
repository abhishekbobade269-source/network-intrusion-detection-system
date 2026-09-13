"""Regression test for a real usability gap found by actually exercising
the API's capture-start flow with a bad path: the capture-thread pump
used to let a `FileNotFoundError` (or anything else) surface as a raw,
unstructured Python traceback with no trace anywhere in the HTTP-facing
API — `DetectionRunner.last_error` gives it somewhere to land.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nids.detection.pipeline import Detection, DetectionEngine
from nids.detection.runner import DetectionRunner
from nids.flows.flow_tracker import FlowTracker
from nids.rules.engine import RuleEngine
from nids.rules.scan_detector import PortScanDetector


async def _noop(_detection: Detection) -> None:
    pass


@pytest.mark.asyncio
async def test_run_pcap_records_last_error_for_a_missing_file(tmp_path: Path) -> None:
    engine = DetectionEngine(
        rule_engine=RuleEngine(rules=[]),
        scan_detector=PortScanDetector(),
        anomaly_scorer=None,
        flow_tracker=FlowTracker(),
        ml_enabled=False,
    )
    runner = DetectionRunner(engine, on_detection=_noop)

    await runner.run_pcap(str(tmp_path / "does-not-exist.pcap"))

    assert runner.last_error is not None
    assert "FileNotFoundError" in runner.last_error
    assert not runner.is_running


@pytest.mark.asyncio
async def test_last_error_resets_on_a_fresh_successful_run(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "demo_traffic.pcap"
    if not fixture.exists():
        pytest.skip("demo fixture missing — run scripts/generate_demo_pcap.py")

    engine = DetectionEngine(
        rule_engine=RuleEngine(rules=[]),
        scan_detector=PortScanDetector(),
        anomaly_scorer=None,
        flow_tracker=FlowTracker(),
        ml_enabled=False,
    )
    runner = DetectionRunner(engine, on_detection=_noop)

    # First run fails and records an error...
    await runner.run_pcap(str(tmp_path / "does-not-exist.pcap"))
    assert runner.last_error is not None

    # ...a later successful run must not leave the stale error behind.
    await runner.run_pcap(str(fixture))
    assert runner.last_error is None
