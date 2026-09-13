from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from nids.alerts.schemas import AlertCreate
from nids.alerts.store import AlertStore
from nids.api.main import create_app
from nids.common import DetectorKind, Severity
from nids.db.session import get_sessionmaker

FIXTURE = Path(__file__).parents[1] / "fixtures" / "demo_traffic.pcap"


@pytest_asyncio.fixture
async def app() -> AsyncIterator[FastAPI]:
    """The FastAPI app with its lifespan (which sets up `app.state.nids`)
    actually driven — plain `ASGITransport` does not run lifespan on its
    own. Separate from `client` below so tests that need to reach into
    `app.state.nids` directly (the capture-guard-clause tests) don't have
    to poke at httpx's private transport attribute to get back to it.
    """
    the_app = create_app()
    async with the_app.router.lifespan_context(the_app):
        yield the_app


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_endpoint_does_not_require_database(client: AsyncClient) -> None:
    response = await client.get("/system/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_capabilities_endpoint_reports_rule_count(client: AsyncClient) -> None:
    response = await client.get("/system/capabilities")

    assert response.status_code == 200
    body = response.json()
    assert body["rules_loaded"] >= 5


@pytest.mark.asyncio
async def test_list_alerts_round_trip(client: AsyncClient, require_database: None) -> None:
    response = await client.get("/alerts", params={"limit": 5})

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_capture_start_replays_pcap_and_alerts_are_queryable(
    require_database: None,
) -> None:
    """Drives the actual HTTP control-plane path — POST /system/capture/start
    with mode=pcap — rather than calling DetectionRunner directly, so this
    is the one test that exercises `nids.api.main._make_on_detection` (the
    callback the live API wires up) instead of a hand-rolled equivalent.
    """
    if not FIXTURE.exists():
        pytest.skip(f"demo fixture missing — run scripts/generate_demo_pcap.py ({FIXTURE})")

    app = create_app()
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            start_response = await client.post(
                "/system/capture/start",
                json={"mode": "pcap", "pcap_path": str(FIXTURE)},
            )
            assert start_response.status_code == 200

            state = app.state.nids
            assert state.runner_task is not None
            await asyncio.wait_for(state.runner_task, timeout=15.0)

            assert state.engine.packets_seen == 90

            alerts_response = await client.get(
                "/alerts", params={"limit": 200, "src_ip": "198.51.100.9"}
            )
            assert alerts_response.status_code == 200
            alerts = alerts_response.json()
            assert alerts, "expected the pcap replay to have produced persisted alerts"
            assert any(a["rule_id"] == "TCP_NULL_SCAN" for a in alerts)

            stats_response = await client.get("/stats/engine")
            assert stats_response.status_code == 200
            assert stats_response.json()["is_capturing"] is False  # replay finished on its own


@pytest.mark.asyncio
async def test_get_alert_returns_404_for_unknown_id(
    client: AsyncClient, require_database: None
) -> None:
    response = await client.get(f"/alerts/{uuid.uuid4()}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_acknowledge_alert_round_trip(client: AsyncClient, require_database: None) -> None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        store = AlertStore(session)
        created = await store.create(
            AlertCreate(
                detector=DetectorKind.SIGNATURE,
                rule_id="API_ACK_TEST",
                name="ack test",
                severity=Severity.LOW,
                confidence=0.5,
                description="ack test",
                src_ip="192.0.2.55",
                dst_ip="192.0.2.56",
            )
        )

    response = await client.get(f"/alerts/{created.id}")
    assert response.status_code == 200
    assert response.json()["acknowledged"] is False

    ack_response = await client.post(f"/alerts/{created.id}/acknowledge")
    assert ack_response.status_code == 200
    assert ack_response.json()["acknowledged"] is True

    missing_response = await client.post(f"/alerts/{uuid.uuid4()}/acknowledge")
    assert missing_response.status_code == 404


class _StubRunningRunner:
    """Minimal stand-in for `DetectionRunner` for the capture-guard-clause
    tests below. `is_running` is read by `AppState.is_capturing`; `stop()`
    is a no-op so the app's own lifespan shutdown (which unconditionally
    calls `state.runner.stop()` if a runner is set) has something to call.
    """

    is_running = True

    def stop(self) -> None:
        pass


@pytest.mark.asyncio
async def test_start_capture_conflicts_when_already_capturing(
    app: FastAPI, client: AsyncClient
) -> None:
    app.state.nids.runner = _StubRunningRunner()

    response = await client.post(
        "/system/capture/start", json={"mode": "pcap", "pcap_path": "irrelevant.pcap"}
    )

    assert response.status_code == 409


@pytest.mark.asyncio
async def test_stop_capture_conflicts_when_not_capturing(client: AsyncClient) -> None:
    response = await client.post("/system/capture/stop")
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_start_live_capture_rejected_when_unavailable(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("nids.api.routes.system.can_capture_live", lambda: False)

    response = await client.post("/system/capture/start", json={"mode": "live", "iface": "eth0"})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_start_pcap_capture_rejected_synchronously_for_a_missing_file(
    client: AsyncClient,
) -> None:
    """Regression test: this used to return 200 "started" for any
    pcap_path, valid or not — the FileNotFoundError only ever surfaced as
    a raw traceback in a background thread, invisible to the caller.
    """
    response = await client.post(
        "/system/capture/start",
        json={"mode": "pcap", "pcap_path": "definitely/does/not/exist.pcap"},
    )

    assert response.status_code == 400
    assert "does not exist" in response.json()["detail"]


@pytest.mark.asyncio
async def test_production_with_no_api_key_generates_one_instead_of_staying_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test for a real gap: a production deployment (exactly
    what docker-compose.yml produces) that forgets to set NIDS_API_KEY
    used to leave every control endpoint completely unauthenticated —
    confirmed exploitable by actually calling capture/start with no key
    against the real container. Fail-safe fix: generate one at startup
    and require it, rather than fail-open.
    """
    from nids.config import get_settings

    if not FIXTURE.exists():
        pytest.skip(f"demo fixture missing — run scripts/generate_demo_pcap.py ({FIXTURE})")

    monkeypatch.setenv("NIDS_ENVIRONMENT", "production")
    monkeypatch.delenv("NIDS_API_KEY", raising=False)
    get_settings.cache_clear()
    try:
        app = create_app()
        async with app.router.lifespan_context(app):
            settings = get_settings()
            assert settings.api_key, "expected a key to be generated for a keyless production run"
            generated_key = settings.api_key

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                no_key_response = await client.post(
                    "/system/capture/start", json={"mode": "pcap", "pcap_path": str(FIXTURE)}
                )
                assert no_key_response.status_code == 401

                wrong_key_response = await client.post(
                    "/system/capture/start",
                    json={"mode": "pcap", "pcap_path": str(FIXTURE)},
                    headers={"X-API-Key": "not-the-real-key"},
                )
                assert wrong_key_response.status_code == 401

                right_key_response = await client.post(
                    "/system/capture/start",
                    json={"mode": "pcap", "pcap_path": str(FIXTURE)},
                    headers={"X-API-Key": generated_key},
                )
                assert right_key_response.status_code == 200

                runner_task = app.state.nids.runner_task
                if runner_task is not None:
                    await asyncio.wait_for(runner_task, timeout=15.0)
    finally:
        get_settings.cache_clear()
