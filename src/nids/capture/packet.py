"""Normalized packet representation.

Both the live sniffer (scapy on a NIC) and the offline pcap/dataset replay
path parse into this same dataclass, so every downstream component (flow
tracker, rule engine, feature extractor) is capture-source agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class TransportProtocol(IntEnum):
    """IANA protocol numbers we care about (subset)."""

    TCP = 6
    UDP = 17
    ICMP = 1
    OTHER = 0


@dataclass(slots=True, frozen=True)
class Packet:
    """A single parsed packet, normalized to the fields detection needs.

    Timestamps are epoch seconds (float) to match scapy and pcap headers.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: TransportProtocol
    src_port: int | None
    dst_port: int | None
    length: int
    ttl: int | None = None
    tcp_flags: str | None = None  # e.g. "S", "SA", "FA", "R" — scapy-style flag letters
    payload_len: int = 0
    raw_summary: str = field(default="", repr=False, compare=False)

    @property
    def flow_key(self) -> tuple[str, str, int, int, int]:
        """Bidirectional-agnostic 5-tuple key ordered so A->B and B->A collide.

        Ordering by (ip, port) pair ensures both directions of one
        conversation map to the same flow.
        """
        a = (self.src_ip, self.src_port or 0)
        b = (self.dst_ip, self.dst_port or 0)
        lo, hi = (a, b) if a <= b else (b, a)
        return (lo[0], hi[0], lo[1], hi[1], int(self.protocol))

    @property
    def is_forward(self) -> bool:
        """True if this packet travels in the flow_key's canonical (lo->hi) direction."""
        a = (self.src_ip, self.src_port or 0)
        b = (self.dst_ip, self.dst_port or 0)
        return a <= b
