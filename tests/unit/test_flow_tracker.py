from nids.capture.packet import Packet, TransportProtocol
from nids.flows.flow_tracker import FlowTracker


def _pkt(
    t: float, src: str, dst: str, sport: int, dport: int, flags: str | None, length: int = 60
) -> Packet:
    return Packet(
        timestamp=t,
        src_ip=src,
        dst_ip=dst,
        protocol=TransportProtocol.TCP,
        src_port=sport,
        dst_port=dport,
        length=length,
        tcp_flags=flags,
    )


def test_flow_finalizes_on_fin() -> None:
    tracker = FlowTracker(idle_timeout_s=100, active_timeout_s=1000)

    assert tracker.update(_pkt(0.0, "10.0.0.1", "10.0.0.2", 5000, 80, "S")) is None
    assert tracker.update(_pkt(0.1, "10.0.0.2", "10.0.0.1", 80, 5000, "SA")) is None
    assert tracker.update(_pkt(0.2, "10.0.0.1", "10.0.0.2", 5000, 80, "A")) is None
    record = tracker.update(_pkt(0.3, "10.0.0.1", "10.0.0.2", 5000, 80, "FA"))

    assert record is not None
    assert record.total_packets == 4
    assert record.fwd_packets == 3  # SYN, ACK, FIN from the 10.0.0.1 side
    assert record.bwd_packets == 1
    assert record.syn_count == 2  # SYN + the SYN bit inside the SYN-ACK
    assert record.ack_count == 3  # SYN-ACK, ACK, FIN-ACK
    assert record.fin_count == 1
    assert tracker.active_flow_count == 0


def test_flow_expires_after_idle_timeout() -> None:
    tracker = FlowTracker(idle_timeout_s=5.0, active_timeout_s=1000)

    tracker.update(_pkt(0.0, "10.0.0.1", "10.0.0.2", 5000, 53, "S"))
    assert tracker.active_flow_count == 1

    # Not idle yet.
    assert tracker.poll(now=4.0) == []
    assert tracker.active_flow_count == 1

    expired = tracker.poll(now=10.0)
    assert len(expired) == 1
    assert tracker.active_flow_count == 0


def test_flush_all_finalizes_every_open_flow() -> None:
    tracker = FlowTracker()
    tracker.update(_pkt(0.0, "10.0.0.1", "10.0.0.2", 1111, 80, "S"))
    tracker.update(_pkt(0.0, "10.0.0.3", "10.0.0.4", 2222, 443, "S"))

    records = tracker.flush_all()

    assert len(records) == 2
    assert tracker.active_flow_count == 0
