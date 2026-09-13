"""Direct repository-layer tests for `AlertStore` against a real Postgres
connection — `create`/`get`/`acknowledge`/`stats` were previously only
exercised indirectly (or not at all) by the API-level tests.
"""

from __future__ import annotations

import uuid

import pytest

from nids.alerts.schemas import AlertCreate
from nids.alerts.store import AlertStore
from nids.common import DetectorKind, Severity
from nids.db.session import get_sessionmaker


def _alert(rule_id: str = "TEST_RULE", src_ip: str = "203.0.113.42") -> AlertCreate:
    return AlertCreate(
        detector=DetectorKind.SIGNATURE,
        rule_id=rule_id,
        name="test alert",
        severity=Severity.HIGH,
        confidence=0.9,
        description="a test alert",
        src_ip=src_ip,
        dst_ip="10.0.0.5",
        src_port=1234,
        dst_port=80,
        protocol=6,
        evidence={"note": "unit test"},
    )


@pytest.mark.asyncio
async def test_create_get_acknowledge_round_trip(require_database: None) -> None:
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as session:
        store = AlertStore(session)
        created = await store.create(_alert())

    assert created.id is not None
    assert created.acknowledged is False

    async with sessionmaker() as session:
        store = AlertStore(session)
        fetched = await store.get(str(created.id))

    assert fetched is not None
    assert fetched.rule_id == "TEST_RULE"

    async with sessionmaker() as session:
        store = AlertStore(session)
        acknowledged = await store.acknowledge(str(created.id))

    assert acknowledged is not None
    assert acknowledged.acknowledged is True


@pytest.mark.asyncio
async def test_get_and_acknowledge_return_none_for_unknown_id(require_database: None) -> None:
    sessionmaker = get_sessionmaker()
    missing_id = str(uuid.uuid4())

    async with sessionmaker() as session:
        store = AlertStore(session)
        assert await store.get(missing_id) is None
        assert await store.acknowledge(missing_id) is None


@pytest.mark.asyncio
async def test_stats_reflects_a_freshly_created_alert(require_database: None) -> None:
    sessionmaker = get_sessionmaker()
    unique_src_ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"

    async with sessionmaker() as session:
        store = AlertStore(session)
        await store.create(_alert(rule_id="STATS_TEST_RULE", src_ip=unique_src_ip))

        stats = await store.stats()

    assert stats.total >= 1
    assert stats.by_severity.get("high", 0) >= 1
    assert stats.by_detector.get("signature", 0) >= 1
    assert any(ip == unique_src_ip for ip, _count in stats.top_src_ips) or stats.total > 10
    # ^ top_src_ips is only the top 10 by count; on a table with a lot of
    # history our one-off IP may not make the cut, so only assert its
    # presence when the table's small enough that it must.


@pytest.mark.asyncio
async def test_list_filters_by_severity_and_src_ip(require_database: None) -> None:
    sessionmaker = get_sessionmaker()
    unique_src_ip = f"192.0.2.{uuid.uuid4().int % 250 + 1}"

    async with sessionmaker() as session:
        store = AlertStore(session)
        await store.create(_alert(rule_id="FILTER_TEST", src_ip=unique_src_ip))

        matching = await store.list(src_ip=unique_src_ip, severity="high")
        non_matching = await store.list(src_ip=unique_src_ip, severity="low")

    assert len(matching) == 1
    assert matching[0].rule_id == "FILTER_TEST"
    assert non_matching == []
