from nids.flows.flow import FlowRecord
from nids.rules.scan_detector import PortScanDetector


def _record(t: float, dst_ip: str, dst_port: int) -> FlowRecord:
    return FlowRecord(
        key=("10.0.0.1", dst_ip, 40000, dst_port, 6),
        protocol=6,  # type: ignore[arg-type]
        src_ip="10.0.0.1",
        dst_ip=dst_ip,
        src_port=40000,
        dst_port=dst_port,
        first_seen=t,
        last_seen=t,
        duration_s=0.001,
        total_packets=1,
        total_bytes=60,
        fwd_packets=1,
        bwd_packets=0,
        fwd_bytes=60,
        bwd_bytes=0,
        fwd_pkt_len_mean=60,
        fwd_pkt_len_std=0,
        fwd_pkt_len_min=60,
        fwd_pkt_len_max=60,
        bwd_pkt_len_mean=0,
        bwd_pkt_len_std=0,
        bwd_pkt_len_min=0,
        bwd_pkt_len_max=0,
        iat_mean=0,
        iat_std=0,
        bytes_per_s=60000,
        packets_per_s=1000,
        down_up_ratio=0,
        syn_count=1,
        ack_count=0,
        fin_count=0,
        rst_count=0,
        psh_count=0,
        urg_count=0,
    )


def test_port_scan_detected_after_threshold_distinct_ports() -> None:
    detector = PortScanDetector(window_s=30, port_scan_threshold=10, host_sweep_threshold=100)

    findings = []
    for port in range(1, 15):
        finding = detector.observe(_record(t=float(port), dst_ip="192.0.2.1", dst_port=port))
        if finding is not None:
            findings.append(finding)

    assert findings, "expected a port-scan finding once the threshold was crossed"
    assert findings[0].rule_id == "HOST_PORT_SCAN"


def test_no_scan_finding_for_ordinary_low_volume_traffic() -> None:
    detector = PortScanDetector(window_s=30, port_scan_threshold=20, host_sweep_threshold=15)

    findings = [
        detector.observe(_record(t=float(i), dst_ip="192.0.2.1", dst_port=443)) for i in range(5)
    ]

    assert all(f is None for f in findings)


def test_activity_outside_window_is_pruned() -> None:
    detector = PortScanDetector(window_s=5, port_scan_threshold=3, host_sweep_threshold=100)

    detector.observe(_record(t=0.0, dst_ip="192.0.2.1", dst_port=1))
    detector.observe(_record(t=1.0, dst_ip="192.0.2.1", dst_port=2))
    # Far outside the 5s window — the two events above should be pruned by now.
    finding = detector.observe(_record(t=100.0, dst_ip="192.0.2.1", dst_port=3))

    assert finding is None
