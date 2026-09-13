"""Broadcasts live detections to connected dashboard websocket clients.

Kept process-local (in-memory) deliberately — for a horizontally-scaled
deployment, swap this for a Redis pub/sub fan-out without changing any
caller, since `broadcast()` is the only method the rest of the app touches.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from fastapi import WebSocket

from nids.detection.pipeline import Detection
from nids.logging_config import get_logger

logger = get_logger(__name__)


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info("ws.connected", clients=len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.info("ws.disconnected", clients=len(self._connections))

    async def broadcast_detection(self, detection: Detection) -> None:
        payload = {
            "type": "detection",
            "at": datetime.now(UTC).isoformat(),
            "rule_id": detection.finding.rule_id,
            "name": detection.finding.name,
            "detector": detection.finding.detector.value,
            "severity": detection.finding.severity.value,
            "confidence": round(detection.finding.confidence, 4),
            "description": detection.finding.description,
            "src_ip": detection.record.src_ip,
            "dst_ip": detection.record.dst_ip,
            "dst_port": detection.record.dst_port,
        }
        await self._broadcast(payload)

    async def broadcast_stats(self, stats: dict) -> None:
        await self._broadcast({"type": "stats", "at": datetime.now(UTC).isoformat(), **stats})

    async def _broadcast(self, payload: dict) -> None:
        if not self._connections:
            return
        message = json.dumps(payload, default=str)
        dead: set[WebSocket] = set()
        async with self._lock:
            targets = set(self._connections)
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:  # noqa: BLE001 — a broken client must not stop the broadcast
                dead.add(ws)
        if dead:
            async with self._lock:
                self._connections -= dead
