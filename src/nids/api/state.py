"""Process-wide singletons the API needs beyond a per-request DB session:
the detection engine, its (possibly running) runner task, and the
websocket broadcaster. Lives on `app.state.nids`, constructed once in the
lifespan handler (`nids.api.main`).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from nids.alerts.notifier import AlertNotifier
from nids.api.ws_manager import WebSocketManager
from nids.detection.pipeline import Detection, DetectionEngine
from nids.detection.runner import DetectionRunner


@dataclass
class AppState:
    engine: DetectionEngine
    notifier: AlertNotifier
    on_detection: Callable[[Detection], Awaitable[None]]
    ws_manager: WebSocketManager = field(default_factory=WebSocketManager)
    runner: DetectionRunner | None = None
    runner_task: asyncio.Task | None = None
    capture_mode: str | None = None  # "live" | "pcap" | None
    capture_source: str | None = None  # iface name or pcap path

    @property
    def is_capturing(self) -> bool:
        return self.runner is not None and self.runner.is_running
