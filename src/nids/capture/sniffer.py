"""Live packet capture off a network interface.

Requires elevated privileges (root / Npcap on Windows / CAP_NET_RAW on
Linux). Imports of scapy are deferred into methods so the rest of the
codebase (API, ML, tests) can run with zero privileges and without
Npcap/libpcap installed.
"""

from __future__ import annotations

import queue
from collections.abc import Iterator

from nids.capture.packet import Packet
from nids.logging_config import get_logger

logger = get_logger(__name__)

_SENTINEL = object()
_QUEUE_MAXSIZE = 10_000
_POLL_TIMEOUT_S = 1.0


class LiveSniffer:
    """Streams normalized `Packet`s off a NIC in near-real-time.

    Runs scapy's AsyncSniffer in a background thread and hands packets to
    the calling thread through a bounded queue, so `packets()` yields as
    frames arrive instead of buffering the whole capture in memory.

    Usage:
        sniffer = LiveSniffer(iface="eth0", bpf_filter="ip")
        for pkt in sniffer.packets():
            handle(pkt)
    """

    def __init__(
        self,
        iface: str | None = None,
        bpf_filter: str = "ip or ip6",
        *,
        count: int = 0,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count  # 0 = unbounded
        self._queue: queue.Queue[object] = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._async_sniffer: object | None = None
        self._dropped = 0

    def stop(self) -> None:
        if self._async_sniffer is not None:
            self._async_sniffer.stop()  # type: ignore[attr-defined]
        self._queue.put(_SENTINEL)

    def packets(self) -> Iterator[Packet]:
        """Yield normalized packets as they arrive until `stop()` is called."""
        from nids.capture._scapy_parse import warm_up_scapy_layers

        # See the matching comment in pcap_reader.iter_pcap: this must run
        # before scapy dissects the first captured packet, not lazily on
        # that same packet inside from_scapy().
        warm_up_scapy_layers()
        from scapy.sendrecv import AsyncSniffer

        from nids.capture._scapy_parse import from_scapy

        def _on_packet(raw: object) -> None:
            try:
                self._queue.put_nowait(raw)
            except queue.Full:
                self._dropped += 1
                if self._dropped % 1000 == 1:
                    logger.warning("sniffer.queue_full", dropped=self._dropped)

        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=_on_packet,
            store=False,
            count=self.count or 0,
        )
        self._async_sniffer = sniffer
        logger.info("sniffer.start", iface=self.iface, filter=self.bpf_filter)
        sniffer.start()
        try:
            while True:
                try:
                    item = self._queue.get(timeout=_POLL_TIMEOUT_S)
                except queue.Empty:
                    if not sniffer.running:
                        break
                    continue
                if item is _SENTINEL:
                    break
                parsed = from_scapy(item)
                if parsed is not None:
                    yield parsed
        finally:
            if sniffer.running:
                sniffer.stop()
            logger.info("sniffer.stop", iface=self.iface, dropped=self._dropped)


def can_capture_live() -> bool:
    """Best-effort probe for whether live capture is possible in this
    environment (interfaces visible, driver present) — used by the API's
    /system/capabilities endpoint and the CLI's startup checks.
    """
    try:
        from scapy.arch import get_if_list

        return len(get_if_list()) > 0
    except Exception:  # noqa: BLE001 — capability probe must never raise
        return False
