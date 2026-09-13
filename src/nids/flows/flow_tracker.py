"""Aggregates a packet stream into flows, emitting `FlowRecord`s when a flow
naturally closes (FIN/RST) or times out (idle or max active duration).

This is the boundary between per-packet capture and per-flow detection: the
rule engine and ML scorer both operate on `FlowRecord`s, not raw packets.
"""

from __future__ import annotations

from nids.capture.packet import Packet
from nids.flows.flow import Flow, FlowKey, FlowRecord
from nids.logging_config import get_logger

logger = get_logger(__name__)


class FlowTracker:
    def __init__(self, idle_timeout_s: float = 15.0, active_timeout_s: float = 120.0) -> None:
        self.idle_timeout_s = idle_timeout_s
        self.active_timeout_s = active_timeout_s
        self._flows: dict[FlowKey, Flow] = {}

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    def update(self, pkt: Packet) -> FlowRecord | None:
        """Feed one packet in. Returns a finalized FlowRecord if this packet
        naturally closed its flow (TCP FIN/RST), else None.
        """
        key = pkt.flow_key
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(
                key=key,
                protocol=pkt.protocol,
                first_seen=pkt.timestamp,
                last_seen=pkt.timestamp,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port or 0,
                dst_port=pkt.dst_port or 0,
            )
            self._flows[key] = flow

        flow.add(pkt)

        if flow.is_terminated:
            del self._flows[key]
            return flow.to_record()
        return None

    def poll(self, now: float) -> list[FlowRecord]:
        """Expire flows that have gone idle or exceeded max active duration.

        Call this periodically (e.g. once per detection-pipeline tick) so
        long-lived or never-closed (UDP, abandoned TCP) flows still get
        scored instead of accumulating forever.
        """
        expired: list[FlowRecord] = []
        stale_keys: list[FlowKey] = []
        for key, flow in self._flows.items():
            idle_for = now - flow.last_seen
            active_for = now - flow.first_seen
            if idle_for >= self.idle_timeout_s or active_for >= self.active_timeout_s:
                stale_keys.append(key)

        for key in stale_keys:
            flow = self._flows.pop(key)
            expired.append(flow.to_record())

        if expired:
            logger.debug("flow_tracker.expired", count=len(expired), remaining=len(self._flows))
        return expired

    def flush_all(self) -> list[FlowRecord]:
        """Force-finalize every in-progress flow — used on shutdown."""
        records = [flow.to_record() for flow in self._flows.values()]
        self._flows.clear()
        return records
