"""End-to-end persistence test: replays the demo pcap through the real
detection pipeline with an `on_detection` callback that writes through
`AlertStore` (the exact code path `nids.api.main._make_on_detection` wires
up for the live API), then reads the rows back — the one part of the
stack the rest of the suite only ever exercised in isolation (unit tests
mock nothing, but nothing before this drove a real flow -> real Postgres
row -> real read-back round trip).

Requires a reachable Postgres (see tests/conftest.py's `require_database`)
and a clean-ish `alerts` table for its own rows to be findable by src_ip;
it doesn't truncate the table itself since other tests/fixtures may share it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nids.alerts.schemas import AlertCreate
from nids.alerts.store import AlertStore
from nids.db.session import get_sessionmaker
from nids.detection.pipeline import Detection, DetectionEngine
from nids.detection.runner import DetectionRunner
from nids.flows.flow_tracker import FlowTracker
from nids.rules.engine import RuleEngine
from nids.rules.loader import load_rules
from nids.rules.scan_detector import PortScanDetector

FIXTURE = Path(__file__).parents[1] / "fixtures" / "demo_traffic.pcap"
RULES_DIR = Path(__file__).parents[2] / "src" / "nids" / "rules" / "definitions"
# A source IP unique to this fixture/run so the read-back query can't
# accidentally match rows some other test/session left behind.
SCAN_SOURCE_IP = "198.51.100.9"


@pytest.mark.asyncio
async def test_detections_persist_and_are_readable(require_database: None) -> None:
    if not FIXTURE.exists():
        pytest.skip(f"demo fixture missing — run scripts/generate_demo_pcap.py ({FIXTURE})")

    engine = DetectionEngine(
        rule_engine=RuleEngine(load_rules(RULES_DIR)),
        scan_detector=PortScanDetector(),
        anomaly_scorer=None,
        flow_tracker=FlowTracker(),
        ml_enabled=False,
    )

    sessionmaker = get_sessionmaker()

    async def _persist(detection: Detection) -> None:
        record, finding = detection.record, detection.finding
        async with sessionmaker() as session:
            store = AlertStore(session)
            await store.create(
                AlertCreate.from_finding(
                    finding,
                    src_ip=record.src_ip,
                    dst_ip=record.dst_ip,
                    src_port=record.src_port,
                    dst_port=record.dst_port,
                    protocol=int(record.protocol),
                )
            )

    runner = DetectionRunner(engine, on_detection=_persist, poll_interval_s=1.0)
    await runner.run_pcap(str(FIXTURE))

    async with sessionmaker() as session:
        store = AlertStore(session)
        rows = await store.list(limit=200, src_ip=SCAN_SOURCE_IP)

    assert rows, "expected at least one persisted alert for the scan source IP"
    rule_ids = {row.rule_id for row in rows}
    assert "TCP_NULL_SCAN" in rule_ids
    assert all(row.src_ip == SCAN_SOURCE_IP for row in rows)
    assert all(row.id is not None and row.created_at is not None for row in rows)
