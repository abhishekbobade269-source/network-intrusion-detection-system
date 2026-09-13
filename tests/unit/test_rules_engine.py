from pathlib import Path

from nids.capture.packet import Packet, TransportProtocol
from nids.flows.flow_tracker import FlowTracker
from nids.rules.engine import RuleEngine
from nids.rules.loader import load_rules

RULES_DIR = Path(__file__).parents[2] / "src" / "nids" / "rules" / "definitions"


def _record_for(flags: str | None, count: int = 1):
    tracker = FlowTracker()
    for _ in range(count):
        tracker.update(
            Packet(
                timestamp=0.0,
                src_ip="203.0.113.5",
                dst_ip="198.51.100.7",
                protocol=TransportProtocol.TCP,
                src_port=40000,
                dst_port=22,
                length=60,
                tcp_flags=flags,
            )
        )
    return tracker.flush_all()[0]


def test_rules_load_without_error() -> None:
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 5
    assert len({r.id for r in rules}) == len(rules)  # no duplicate ids


def test_null_scan_rule_fires_on_flagless_flow() -> None:
    engine = RuleEngine(load_rules(RULES_DIR))
    record = _record_for(flags="")

    findings = engine.evaluate(record)

    assert any(f.rule_id == "TCP_NULL_SCAN" for f in findings)


def test_normal_handshake_flow_does_not_fire_scan_rules() -> None:
    tracker = FlowTracker()
    pkts = [
        ("203.0.113.5", "198.51.100.7", 40000, 443, "S"),
        ("198.51.100.7", "203.0.113.5", 443, 40000, "SA"),
        ("203.0.113.5", "198.51.100.7", 40000, 443, "A"),
        ("203.0.113.5", "198.51.100.7", 40000, 443, "PA"),
        ("198.51.100.7", "203.0.113.5", 443, 40000, "PA"),
        ("203.0.113.5", "198.51.100.7", 40000, 443, "FA"),
    ]
    record = None
    for src, dst, sport, dport, flags in pkts:
        record = tracker.update(
            Packet(
                timestamp=0.0,
                src_ip=src,
                dst_ip=dst,
                protocol=TransportProtocol.TCP,
                src_port=sport,
                dst_port=dport,
                length=200,
                tcp_flags=flags,
            )
        )

    assert record is not None
    engine = RuleEngine(load_rules(RULES_DIR))
    findings = engine.evaluate(record)
    scan_findings = [f for f in findings if "SCAN" in f.rule_id]
    assert scan_findings == []
