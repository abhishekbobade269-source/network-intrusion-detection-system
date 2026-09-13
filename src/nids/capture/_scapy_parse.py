"""Shared scapy-packet -> `Packet` normalization used by both the live sniffer
and the offline pcap reader, so the two capture paths can never drift apart.
"""

from __future__ import annotations

import time
from typing import Any

from nids.capture.packet import Packet, TransportProtocol

_warmed_up = False


def warm_up_scapy_layers() -> None:
    """Import every scapy layer module `from_scapy` relies on, up front.

    Scapy registers its Ether<->IP<->{TCP,UDP,ICMP} `bind_layers` payload
    dispatch as an import-time side effect of `scapy.layers.l2` /
    `scapy.layers.inet` / `scapy.layers.inet6`. A `Packet` is dissected into
    its sub-layers exactly once, eagerly, the moment it's read off the wire
    or out of a pcap — so if those bindings aren't registered *yet* at that
    moment, the payload is parsed as an opaque `Raw` layer forever, no
    matter what gets imported afterwards.

    Call this before starting to read/sniff — not lazily inside
    `from_scapy()` on the first packet itself, which is one packet too
    late and used to silently drop exactly the first packet of every
    capture session.
    """
    global _warmed_up
    if _warmed_up:
        return
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.inet6  # noqa: F401
    import scapy.layers.l2  # noqa: F401

    _warmed_up = True


def from_scapy(pkt: Any) -> Packet | None:  # noqa: ANN401 — scapy has no stable type stubs
    """Parse one scapy packet into a `Packet`, or None if it has no IP layer.

    Assumes `warm_up_scapy_layers()` has already run (both capture entry
    points — `LiveSniffer.packets()` and `iter_pcap()` — call it before
    reading anything); it is not repeated here since by the time a `pkt`
    reaches this function it has already been dissected.
    """
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip_layer is None:
        return None

    ts = float(getattr(pkt, "time", time.time()))
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    ttl = getattr(ip_layer, "ttl", None) or getattr(ip_layer, "hlim", None)
    length = len(pkt)

    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    payload_len = 0
    protocol = TransportProtocol.OTHER

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        protocol = TransportProtocol.TCP
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        tcp_flags = str(tcp.flags)
        payload_len = len(bytes(tcp.payload))
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        protocol = TransportProtocol.UDP
        src_port, dst_port = int(udp.sport), int(udp.dport)
        payload_len = len(bytes(udp.payload))
    elif pkt.haslayer(ICMP):
        protocol = TransportProtocol.ICMP

    return Packet(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        ttl=ttl,
        tcp_flags=tcp_flags,
        payload_len=payload_len,
        raw_summary=pkt.summary() if hasattr(pkt, "summary") else "",
    )
