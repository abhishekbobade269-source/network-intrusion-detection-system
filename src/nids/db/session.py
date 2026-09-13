"""Async engine/session factory.

A single lazily-created engine is reused for the process lifetime; FastAPI
gets a session per request via `get_session` as a dependency.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from nids.config import get_settings


@lru_cache
def init_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=init_engine(), expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: `session: AsyncSession = Depends(get_session)`."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session
