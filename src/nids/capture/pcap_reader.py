"""Offline capture source: replay a .pcap/.pcapng file through the same
normalization path the live sniffer uses, so rules/ML never know the
difference. This is what makes the pipeline demoable and testable without
root/NIC access or a live attack on the wire.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from nids.capture.packet import Packet
from nids.logging_config import get_logger

logger = get_logger(__name__)


def iter_pcap(path: str | Path) -> Iterator[Packet]:
    """Lazily yield normalized packets from a pcap/pcapng file on disk.

    Uses scapy's PcapReader for streaming (constant memory) rather than
    rdpcap, which loads the whole capture into memory — important for the
    multi-GB captures typical of public IDS datasets.
    """
    from nids.capture._scapy_parse import warm_up_scapy_layers

    # Must happen before the reader dissects its first packet, not lazily
    # inside from_scapy() on that same packet — scapy binds Ether's payload
    # to IP/IPv6 (and IP's to TCP/UDP/ICMP) at import time, and a Packet's
    # dissection into sub-layers happens once, eagerly, the moment it's
    # read off the wire/file. Warming up one packet too late silently
    # mis-parses exactly that one packet as an opaque Raw payload — which
    # is exactly what bit the very first packet of every capture session
    # before this was pulled out of from_scapy()'s per-call deferred import.
    warm_up_scapy_layers()
    from scapy.utils import PcapReader

    from nids.capture._scapy_parse import from_scapy

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"pcap file not found: {path}")

    logger.info("pcap.replay_start", path=str(path))
    count = 0
    with PcapReader(str(path)) as reader:
        for raw in reader:
            parsed = from_scapy(raw)
            count += 1
            if parsed is not None:
                yield parsed
    logger.info("pcap.replay_end", path=str(path), packets_read=count)
