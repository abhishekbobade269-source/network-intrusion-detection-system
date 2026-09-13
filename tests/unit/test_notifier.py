"""Tests `AlertNotifier` against a *real* local HTTP server (stdlib
`http.server` on an ephemeral port, in a background thread) rather than
mocking `httpx` itself — this exercises the actual POST request the
notifier sends over a real socket, including that a webhook failure never
raises out of `notify()`.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from nids.alerts.notifier import AlertNotifier
from nids.common import Severity


class _CapturingHandler(BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's naming convention
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _CapturingHandler.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — stdlib signature
        pass  # quiet test output


@pytest.fixture
def webhook_server() -> Iterator[str]:
    _CapturingHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/hook"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.asyncio
async def test_notify_posts_expected_payload_to_webhook(webhook_server: str) -> None:
    notifier = AlertNotifier(webhook_server, min_severity=Severity.LOW)

    await notifier.notify(
        rule_id="TCP_NULL_SCAN",
        name="TCP NULL scan probe",
        severity=Severity.MEDIUM,
        description="test description",
        src_ip="198.51.100.9",
        dst_ip="10.0.0.5",
    )

    assert len(_CapturingHandler.received) == 1
    payload = _CapturingHandler.received[0]
    assert payload["rule_id"] == "TCP_NULL_SCAN"
    assert payload["severity"] == "medium"
    assert payload["src_ip"] == "198.51.100.9"


@pytest.mark.asyncio
async def test_notify_skips_when_below_severity_floor(webhook_server: str) -> None:
    notifier = AlertNotifier(webhook_server, min_severity=Severity.HIGH)

    await notifier.notify(
        rule_id="LOW_SEV",
        name="low severity thing",
        severity=Severity.LOW,
        description="should not be sent",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )

    assert _CapturingHandler.received == []


@pytest.mark.asyncio
async def test_notify_is_a_noop_without_a_webhook_url() -> None:
    notifier = AlertNotifier(None)
    # Must not raise even though there's nowhere to send it.
    await notifier.notify(
        rule_id="X",
        name="X",
        severity=Severity.CRITICAL,
        description="X",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )


@pytest.mark.asyncio
async def test_notify_swallows_connection_failures() -> None:
    # Nothing listens on this port — the POST must fail internally without
    # notify() itself raising, so a flaky webhook can never take detection down.
    notifier = AlertNotifier("http://127.0.0.1:1/unreachable", min_severity=Severity.LOW)

    await notifier.notify(
        rule_id="X",
        name="X",
        severity=Severity.CRITICAL,
        description="X",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
    )
