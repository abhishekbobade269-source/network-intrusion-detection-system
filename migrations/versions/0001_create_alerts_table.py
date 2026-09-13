"""create alerts table

Revision ID: 0001
Revises:
Create Date: 2026-09-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("detector", sa.String(length=16), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("dst_ip", sa.String(length=45), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dst_port", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("protocol", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_src_ip", table_name="alerts")
    op.drop_index("ix_alerts_created_at", table_name="alerts")
    op.drop_table("alerts")
