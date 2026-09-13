"""Packet acquisition: live NIC capture and offline pcap replay, both yielding
the same normalized `Packet` model so downstream code never branches on source.
"""

from nids.capture.packet import Packet, TransportProtocol
from nids.capture.pcap_reader import iter_pcap
from nids.capture.sniffer import LiveSniffer

__all__ = ["LiveSniffer", "Packet", "TransportProtocol", "iter_pcap"]
