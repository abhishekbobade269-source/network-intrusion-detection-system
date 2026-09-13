"""Async orchestration layer: drives the synchronous `DetectionEngine` from
either a live NIC or a replayed pcap, and hands each `Detection` to an async
callback (persist to Postgres, notify, broadcast over the dashboard
websocket — see `nids.api`).

Both capture sources are synchronous, (potentially) blocking generators, so
each is pumped from a dedicated background thread into an `asyncio.Queue`
via `loop.call_soon_threadsafe` — the event loop itself never blocks on
packet I/O.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable

from nids.capture.packet import Packet
from nids.capture.pcap_reader import iter_pcap
from nids.capture.sniffer import LiveSniffer
from nids.detection.pipeline import Detection, DetectionEngine
from nids.logging_config import get_logger

logger = get_logger(__name__)

_QUEUE_MAXSIZE = 50_000
_SHUTDOWN = object()


class DetectionRunner:
    def __init__(
        self,
        engine: DetectionEngine,
        on_detection: Callable[[Detection], Awaitable[None]],
        poll_interval_s: float = 5.0,
    ) -> None:
        self.engine = engine
        self.on_detection = on_detection
        self.poll_interval_s = poll_interval_s
        self._live_sniffer: LiveSniffer | None = None
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def stop(self) -> None:
        self._running = False
        if self._live_sniffer is not None:
            self._live_sniffer.stop()

    async def run_live(self, iface: str | None, bpf_filter: str) -> None:
        sniffer = LiveSniffer(iface=iface, bpf_filter=bpf_filter)
        self._live_sniffer = sniffer
        await self._consume(sniffer.packets(), clock=time.time)

    async def run_pcap(self, path: str) -> None:
        # Offline replay: expire flows against packet (capture) time, not
        # wall-clock time, so idle/active timeouts behave the same whether
        # a file replays in 2 seconds or 20 minutes.
        last_ts = time.time()

        def _pcap_clock() -> float:
            return last_ts

        def _tracking_iter() -> Iterable[Packet]:
            nonlocal last_ts
            for pkt in iter_pcap(path):
                last_ts = pkt.timestamp
                yield pkt

        await self._consume(_tracking_iter(), clock=_pcap_clock)

    async def _consume(self, packets: Iterable[Packet], clock: Callable[[], float]) -> None:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[object] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        self._running = True

        def _pump() -> None:
            try:
                for pkt in packets:
                    if not self._running:
                        break
                    loop.call_soon_threadsafe(queue.put_nowait, pkt)
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, _SHUTDOWN)

        thread = threading.Thread(target=_pump, name="nids-capture-pump", daemon=True)
        thread.start()

        try:
            async for item in self._drain(queue, clock):
                for detection in self.engine.handle_packet(item):
                    await self.on_detection(detection)
        finally:
            self._running = False
            thread.join(timeout=5.0)
            for detection in self.engine.flush():
                await self.on_detection(detection)

    async def _drain(
        self, queue: asyncio.Queue[object], clock: Callable[[], float]
    ) -> AsyncIterator[Packet]:
        last_poll = clock()
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=self.poll_interval_s)
            except TimeoutError:
                item = None

            if item is _SHUTDOWN:
                return
            if item is not None:
                yield item  # type: ignore[misc]

            now = clock()
            if now - last_poll >= self.poll_interval_s:
                last_poll = now
                for detection in self.engine.poll(now):
                    await self.on_detection(detection)
