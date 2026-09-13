"""Flow state and the running statistics used to build ML feature vectors.

Feature set is a deliberately-scoped subset of the CICFlowMeter-style
features widely used in NIDS literature (CICIDS2017/NSL-KDD-adjacent):
volumetric counts, inter-arrival timing, packet-length distribution and
TCP flag counts. Enough to separate scans/floods/exfil-like patterns from
normal traffic without the 80+-feature surface area of the full tool.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from nids.capture.packet import Packet, TransportProtocol

FlowKey = tuple[str, str, int, int, int]


@dataclass(slots=True)
class _RunningStats:
    """Welford's online algorithm — mean/variance in one pass, no stored samples."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)
        self.minimum = min(self.minimum, x)
        self.maximum = max(self.maximum, x)

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self.m2 / self.n)

    @property
    def safe_min(self) -> float:
        return 0.0 if math.isinf(self.minimum) else self.minimum

    @property
    def safe_max(self) -> float:
        return 0.0 if math.isinf(self.maximum) else self.maximum


TCP_FLAG_LETTERS = ("S", "A", "F", "R", "P", "U")  # SYN ACK FIN RST PSH URG


@dataclass(slots=True)
class Flow:
    """Mutable, in-progress bidirectional flow."""

    key: FlowKey
    protocol: TransportProtocol
    first_seen: float
    last_seen: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_len_stats: _RunningStats = field(default_factory=_RunningStats)
    bwd_len_stats: _RunningStats = field(default_factory=_RunningStats)
    iat_stats: _RunningStats = field(default_factory=_RunningStats)  # inter-arrival time, all pkts
    flag_counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(TCP_FLAG_LETTERS, 0))
    _last_pkt_time: float = 0.0

    def add(self, pkt: Packet) -> None:
        if self._last_pkt_time:
            self.iat_stats.update(max(0.0, pkt.timestamp - self._last_pkt_time))
        self._last_pkt_time = pkt.timestamp
        self.last_seen = pkt.timestamp

        if pkt.is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.length
            self.fwd_len_stats.update(float(pkt.length))
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.length
            self.bwd_len_stats.update(float(pkt.length))

        if pkt.tcp_flags:
            for letter in pkt.tcp_flags:
                if letter in self.flag_counts:
                    self.flag_counts[letter] += 1

    @property
    def is_terminated(self) -> bool:
        """True once a FIN or RST has been observed (natural TCP close)."""
        return self.flag_counts.get("F", 0) > 0 or self.flag_counts.get("R", 0) > 0

    def to_record(self) -> FlowRecord:
        duration = max(1e-6, self.last_seen - self.first_seen)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        return FlowRecord(
            key=self.key,
            protocol=self.protocol,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            duration_s=duration,
            total_packets=total_packets,
            total_bytes=total_bytes,
            fwd_packets=self.fwd_packets,
            bwd_packets=self.bwd_packets,
            fwd_bytes=self.fwd_bytes,
            bwd_bytes=self.bwd_bytes,
            fwd_pkt_len_mean=self.fwd_len_stats.mean,
            fwd_pkt_len_std=self.fwd_len_stats.std,
            fwd_pkt_len_min=self.fwd_len_stats.safe_min,
            fwd_pkt_len_max=self.fwd_len_stats.safe_max,
            bwd_pkt_len_mean=self.bwd_len_stats.mean,
            bwd_pkt_len_std=self.bwd_len_stats.std,
            bwd_pkt_len_min=self.bwd_len_stats.safe_min,
            bwd_pkt_len_max=self.bwd_len_stats.safe_max,
            iat_mean=self.iat_stats.mean,
            iat_std=self.iat_stats.std,
            bytes_per_s=total_bytes / duration,
            packets_per_s=total_packets / duration,
            down_up_ratio=(self.bwd_packets / self.fwd_packets) if self.fwd_packets else 0.0,
            syn_count=self.flag_counts.get("S", 0),
            ack_count=self.flag_counts.get("A", 0),
            fin_count=self.flag_counts.get("F", 0),
            rst_count=self.flag_counts.get("R", 0),
            psh_count=self.flag_counts.get("P", 0),
            urg_count=self.flag_counts.get("U", 0),
        )


@dataclass(slots=True, frozen=True)
class FlowRecord:
    """Finalized, immutable flow — the unit fed to the rule engine and the ML model."""

    key: FlowKey
    protocol: TransportProtocol
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    first_seen: float
    last_seen: float
    duration_s: float
    total_packets: int
    total_bytes: int
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    fwd_pkt_len_mean: float
    fwd_pkt_len_std: float
    fwd_pkt_len_min: float
    fwd_pkt_len_max: float
    bwd_pkt_len_mean: float
    bwd_pkt_len_std: float
    bwd_pkt_len_min: float
    bwd_pkt_len_max: float
    iat_mean: float
    iat_std: float
    bytes_per_s: float
    packets_per_s: float
    down_up_ratio: float
    syn_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    psh_count: int
    urg_count: int

    #: Column order the ML pipeline trains on and scores against — keep in
    #: sync with `nids.ml.features.FEATURE_COLUMNS`.
    def to_feature_dict(self) -> dict[str, float]:
        return {
            "duration_s": self.duration_s,
            "total_packets": float(self.total_packets),
            "total_bytes": float(self.total_bytes),
            "fwd_packets": float(self.fwd_packets),
            "bwd_packets": float(self.bwd_packets),
            "fwd_bytes": float(self.fwd_bytes),
            "bwd_bytes": float(self.bwd_bytes),
            "fwd_pkt_len_mean": self.fwd_pkt_len_mean,
            "fwd_pkt_len_std": self.fwd_pkt_len_std,
            "fwd_pkt_len_min": self.fwd_pkt_len_min,
            "fwd_pkt_len_max": self.fwd_pkt_len_max,
            "bwd_pkt_len_mean": self.bwd_pkt_len_mean,
            "bwd_pkt_len_std": self.bwd_pkt_len_std,
            "bwd_pkt_len_min": self.bwd_pkt_len_min,
            "bwd_pkt_len_max": self.bwd_pkt_len_max,
            "iat_mean": self.iat_mean,
            "iat_std": self.iat_std,
            "bytes_per_s": self.bytes_per_s,
            "packets_per_s": self.packets_per_s,
            "down_up_ratio": self.down_up_ratio,
            "syn_count": float(self.syn_count),
            "ack_count": float(self.ack_count),
            "fin_count": float(self.fin_count),
            "rst_count": float(self.rst_count),
            "psh_count": float(self.psh_count),
            "urg_count": float(self.urg_count),
        }
