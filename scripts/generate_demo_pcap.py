"""Generates a small, deterministic demo pcap with a mix of benign and
attack-shaped traffic — used by the integration test suite and by
`README.md`'s quickstart so `nids replay` has something to show without
needing a real network capture.

    python scripts/generate_demo_pcap.py [output_path]

Frames are wrapped in Ether() (not bare IP()) so scapy's built-in
linktype table can decode them back without libpcap/Npcap installed —
see `nids.capture.sniffer`/`pcap_reader`'s `import scapy.layers.l2` for
why that registration matters.
"""

from __future__ import annotations

import sys
from pathlib import Path

DEFAULT_OUTPUT = Path(__file__).parents[1] / "tests" / "fixtures" / "demo_traffic.pcap"


def build_packets() -> list:
    from scapy.layers.inet import ICMP, IP, TCP
    from scapy.layers.l2 import Ether

    packets = []
    t = 1_700_000_000.0

    # A normal HTTPS-ish handshake + a couple of data packets + close —
    # must NOT trigger any rule or the anomaly model.
    for i, flags in enumerate(["S", "SA", "A", "PA", "PA", "FA"]):
        if i % 2 == 0:
            src, dst, sport, dport = "10.0.0.5", "93.184.216.34", 51000, 443
        else:
            src, dst, sport, dport = "93.184.216.34", "10.0.0.5", 443, 51000
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        pkt.time = t
        t += 0.05
        packets.append(pkt)

    # A TCP NULL-scan sweep across 24 ports from one source — should trip
    # both TCP_NULL_SCAN (per-flow) and HOST_PORT_SCAN (cross-flow).
    for port in range(1, 25):
        pkt = (
            Ether()
            / IP(src="198.51.100.9", dst="10.0.0.5")
            / TCP(sport=40000 + port, dport=port, flags="")
        )
        pkt.time = t
        t += 0.01
        packets.append(pkt)

    # An ICMP flood — should trip ICMP_FLOOD.
    for _ in range(60):
        pkt = Ether() / IP(src="203.0.113.9", dst="10.0.0.5") / ICMP()
        pkt.time = t
        t += 0.002
        packets.append(pkt)

    return packets


def main() -> None:
    from scapy.utils import wrpcap

    output = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    wrpcap(str(output), packets)
    print(f"wrote {len(packets)} packets to {output}")


if __name__ == "__main__":
    main()
