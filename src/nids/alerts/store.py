"""Repository layer over the `alerts` table — the only place in the codebase
that should issue SQL for alerts, so query patterns and indexes stay in one
auditable spot.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from nids.alerts.models import AlertORM
from nids.alerts.schemas import AlertCreate, AlertStats
from nids.logging_config import get_logger

logger = get_logger(__name__)


class AlertStore:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, alert: AlertCreate) -> AlertORM:
        row = AlertORM(**alert.model_dump())
        self.session.add(row)
        await self.session.commit()
        await self.session.refresh(row)
        logger.info("alert.created", id=str(row.id), rule_id=row.rule_id, severity=row.severity)
        return row

    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        src_ip: str | None = None,
        detector: str | None = None,
    ) -> list[AlertORM]:
        stmt = select(AlertORM).order_by(AlertORM.created_at.desc()).limit(limit).offset(offset)
        if severity:
            stmt = stmt.where(AlertORM.severity == severity)
        if src_ip:
            stmt = stmt.where(AlertORM.src_ip == src_ip)
        if detector:
            stmt = stmt.where(AlertORM.detector == detector)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get(self, alert_id: str) -> AlertORM | None:
        return await self.session.get(AlertORM, alert_id)

    async def acknowledge(self, alert_id: str) -> AlertORM | None:
        row = await self.get(alert_id)
        if row is None:
            return None
        row.acknowledged = True
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def stats(self) -> AlertStats:
        total = (await self.session.execute(select(func.count(AlertORM.id)))).scalar_one()

        by_severity_rows = await self.session.execute(
            select(AlertORM.severity, func.count(AlertORM.id)).group_by(AlertORM.severity)
        )
        by_detector_rows = await self.session.execute(
            select(AlertORM.detector, func.count(AlertORM.id)).group_by(AlertORM.detector)
        )
        top_src_rows = await self.session.execute(
            select(AlertORM.src_ip, func.count(AlertORM.id).label("n"))
            .group_by(AlertORM.src_ip)
            .order_by(func.count(AlertORM.id).desc())
            .limit(10)
        )
        return AlertStats(
            total=total,
            by_severity={row[0]: row[1] for row in by_severity_rows.all()},
            by_detector={row[0]: row[1] for row in by_detector_rows.all()},
            top_src_ips=[tuple(row) for row in top_src_rows.all()],
        )
