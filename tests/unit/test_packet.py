from nids.capture.packet import Packet, TransportProtocol


def _pkt(src_ip: str, dst_ip: str, src_port: int, dst_port: int, **kwargs) -> Packet:
    return Packet(
        timestamp=0.0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=TransportProtocol.TCP,
        src_port=src_port,
        dst_port=dst_port,
        length=60,
        **kwargs,
    )


def test_flow_key_is_symmetric_across_directions() -> None:
    forward = _pkt("10.0.0.1", "10.0.0.2", 5000, 443)
    reverse = _pkt("10.0.0.2", "10.0.0.1", 443, 5000)

    assert forward.flow_key == reverse.flow_key


def test_is_forward_matches_canonical_direction() -> None:
    forward = _pkt("10.0.0.1", "10.0.0.2", 5000, 443)
    reverse = _pkt("10.0.0.2", "10.0.0.1", 443, 5000)

    assert forward.is_forward != reverse.is_forward


def test_flow_key_distinguishes_different_conversations() -> None:
    a = _pkt("10.0.0.1", "10.0.0.2", 5000, 443)
    b = _pkt("10.0.0.1", "10.0.0.3", 5000, 443)

    assert a.flow_key != b.flow_key
