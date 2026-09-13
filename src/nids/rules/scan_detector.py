"""Stateful, cross-flow signatures that a single flow's fields can't express
on their own — chiefly host-based port/host scan detection, which needs to
watch how many distinct destinations one source touches over a time window.

Kept separate from the YAML `RuleEngine` because this needs mutable
sliding-window state per source IP, not a stateless per-flow predicate.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from nids.common import DetectorKind, Finding, Severity
from nids.flows.flow import FlowRecord
from nids.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class _SourceActivity:
    # (timestamp, dst_ip, dst_port) observations within the sliding window
    events: deque[tuple[float, str, int]] = field(default_factory=deque)

    def prune(self, now: float, window_s: float) -> None:
        cutoff = now - window_s
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def distinct_ports(self) -> int:
        return len({(dst_ip, dst_port) for _, dst_ip, dst_port in self.events})

    def distinct_hosts(self) -> int:
        return len({dst_ip for _, dst_ip, _ in self.events})


class PortScanDetector:
    """Flags a source IP that touches an unusually large number of distinct
    (host, port) pairs within a sliding time window — the classic signature
    of a TCP/UDP port scan (e.g. nmap) or host-discovery sweep.
    """

    def __init__(
        self,
        window_s: float = 30.0,
        port_scan_threshold: int = 20,
        host_sweep_threshold: int = 15,
    ) -> None:
        self.window_s = window_s
        self.port_scan_threshold = port_scan_threshold
        self.host_sweep_threshold = host_sweep_threshold
        self._by_source: dict[str, _SourceActivity] = {}

    def observe(self, record: FlowRecord) -> Finding | None:
        activity = self._by_source.setdefault(record.src_ip, _SourceActivity())
        activity.events.append((record.last_seen, record.dst_ip, record.dst_port))
        activity.prune(record.last_seen, self.window_s)

        ports = activity.distinct_ports()
        hosts = activity.distinct_hosts()

        if ports >= self.port_scan_threshold:
            logger.info("scan_detector.port_scan", src_ip=record.src_ip, distinct_ports=ports)
            return Finding(
                detector=DetectorKind.SIGNATURE,
                rule_id="HOST_PORT_SCAN",
                name="Port scan detected",
                severity=Severity.HIGH,
                confidence=min(0.95, 0.5 + ports / (2 * self.port_scan_threshold)),
                description=(
                    f"{record.src_ip} touched {ports} distinct (host, port) pairs "
                    f"in the last {self.window_s:.0f}s"
                ),
                evidence={
                    "src_ip": record.src_ip,
                    "distinct_ports": ports,
                    "window_s": self.window_s,
                },
            )
        if hosts >= self.host_sweep_threshold:
            logger.info("scan_detector.host_sweep", src_ip=record.src_ip, distinct_hosts=hosts)
            return Finding(
                detector=DetectorKind.SIGNATURE,
                rule_id="HOST_SWEEP",
                name="Host sweep detected",
                severity=Severity.MEDIUM,
                confidence=min(0.9, 0.4 + hosts / (2 * self.host_sweep_threshold)),
                description=(
                    f"{record.src_ip} contacted {hosts} distinct hosts "
                    f"in the last {self.window_s:.0f}s"
                ),
                evidence={
                    "src_ip": record.src_ip,
                    "distinct_hosts": hosts,
                    "window_s": self.window_s,
                },
            )
        return None

    def reset(self) -> None:
        self._by_source.clear()
