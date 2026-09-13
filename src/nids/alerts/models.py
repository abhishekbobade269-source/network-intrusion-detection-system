"""SQLAlchemy ORM model for a persisted alert.

An `Alert` is what the detection pipeline produces after combining one or
more `Finding`s (signature and/or ML) for the same flow into a single
storable, queryable, notifiable record.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from nids.db.base import Base


class AlertORM(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_created_at", "created_at"),
        Index("ix_alerts_src_ip", "src_ip"),
        Index("ix_alerts_severity", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    detector: Mapped[str] = mapped_column(String(16), nullable=False)  # signature | anomaly
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)  # v6-safe width
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    protocol: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    acknowledged: Mapped[bool] = mapped_column(default=False, nullable=False)
