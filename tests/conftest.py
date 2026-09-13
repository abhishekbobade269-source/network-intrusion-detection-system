from __future__ import annotations

import os

import pytest

os.environ.setdefault("NIDS_ENVIRONMENT", "test")
os.environ.setdefault("NIDS_ML_ENABLED", "false")
os.environ.setdefault(
    "NIDS_DATABASE_URL", "postgresql+asyncpg://nids:nids@localhost:5432/nids_test"
)


async def _database_reachable() -> bool:
    from sqlalchemy.ext.asyncio import create_async_engine

    from nids.config import get_settings

    engine = create_async_engine(get_settings().database_url)
    try:
        async with engine.connect():
            return True
    except Exception:  # noqa: BLE001 — connectivity probe, any failure means "skip"
        return False
    finally:
        await engine.dispose()


@pytest.fixture
async def require_database() -> None:
    """Skip a test at runtime if no Postgres is reachable — keeps `pytest`
    green on a laptop with no DB running, while CI (which starts a real
    postgres service) exercises the full path.
    """
    if not await _database_reachable():
        pytest.skip("Postgres not reachable at NIDS_DATABASE_URL — skipping DB-backed test")
