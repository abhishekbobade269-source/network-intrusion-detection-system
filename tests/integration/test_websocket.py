"""Drives /ws/alerts through a real ASGI websocket handshake (Starlette's
TestClient) to exercise `WebSocketManager.connect`/`disconnect` for real,
plus a focused unit test of the broadcast fan-out / dead-connection
pruning logic in `broadcast_detection` against minimal fake sockets (one
raising on send, to prove one dead client can't block delivery to the
others).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from nids.api.main import create_app
from nids.api.ws_manager import WebSocketManager
from nids.common import DetectorKind, Finding, Severity
from nids.detection.pipeline import Detection
from nids.flows.flow import FlowRecord


def test_websocket_endpoint_accepts_and_closes_cleanly() -> None:
    app = create_app()
    with TestClient(app) as client, client.websocket_connect("/ws/alerts") as websocket:
        assert app.state.nids.ws_manager is not None
        websocket.close()


def _record() -> FlowRecord:
    return FlowRecord(
        key=("10.0.0.1", "10.0.0.2", 1, 2, 6),
        protocol=6,  # type: ignore[arg-type]
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1,
        dst_port=2,
        first_seen=0.0,
        last_seen=0.0,
        duration_s=1.0,
        total_packets=1,
        total_bytes=60,
        fwd_packets=1,
        bwd_packets=0,
        fwd_bytes=60,
        bwd_bytes=0,
        fwd_pkt_len_mean=60,
        fwd_pkt_len_std=0,
        fwd_pkt_len_min=60,
        fwd_pkt_len_max=60,
        bwd_pkt_len_mean=0,
        bwd_pkt_len_std=0,
        bwd_pkt_len_min=0,
        bwd_pkt_len_max=0,
        iat_mean=0,
        iat_std=0,
        bytes_per_s=60,
        packets_per_s=1,
        down_up_ratio=0,
        syn_count=1,
        ack_count=0,
        fin_count=0,
        rst_count=0,
        psh_count=0,
        urg_count=0,
    )


@dataclass(eq=False)  # identity-based hash/eq — instances live in a `set` below
class _FakeSocket:
    sent: list[str]
    fail: bool = False

    async def send_text(self, message: str) -> None:
        if self.fail:
            raise RuntimeError("connection reset")
        self.sent.append(message)


@pytest.mark.asyncio
async def test_broadcast_prunes_dead_sockets_without_blocking_live_ones() -> None:
    manager = WebSocketManager()
    good = _FakeSocket(sent=[])
    dead = _FakeSocket(sent=[], fail=True)
    manager._connections = {good, dead}  # type: ignore[arg-type] # noqa: SLF001 — test-only setup

    finding = Finding(
        detector=DetectorKind.SIGNATURE,
        rule_id="TEST_RULE",
        name="test",
        severity=Severity.HIGH,
        confidence=0.9,
        description="test finding",
    )
    await manager.broadcast_detection(Detection(record=_record(), finding=finding))

    assert len(good.sent) == 1
    assert "TEST_RULE" in good.sent[0]
    assert good in manager._connections  # noqa: SLF001
    assert dead not in manager._connections  # noqa: SLF001 — pruned after the failed send
