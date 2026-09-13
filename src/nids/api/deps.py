"""FastAPI dependency providers."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, Header, HTTPException, Request, WebSocket, status
from sqlalchemy.ext.asyncio import AsyncSession

from nids.alerts.store import AlertStore
from nids.api.state import AppState
from nids.config import Settings, get_settings
from nids.db.session import get_session


async def get_app_state(request: Request) -> AppState:
    return request.app.state.nids


async def get_app_state_ws(websocket: WebSocket) -> AppState:
    """The websocket-route equivalent of `get_app_state`.

    FastAPI resolves a sub-dependency's connection object by the type
    annotation it declares (`Request` vs. `WebSocket`) — a websocket
    endpoint has no `Request` to inject, so `get_app_state` alone throws a
    confusing "missing 1 required positional argument" at call time for
    any websocket route that depends on it. Keep the two separate rather
    than trying to make one function accept either.
    """
    return websocket.app.state.nids


async def get_alert_store(
    session: AsyncSession = Depends(get_session),
) -> AsyncIterator[AlertStore]:
    yield AlertStore(session)


def require_api_key(
    settings: Settings = Depends(get_settings),
    x_api_key: str | None = Header(default=None),
) -> None:
    """Gate write/control endpoints behind a static API key when one is
    configured (NIDS_API_KEY). No-op in local dev when unset — never
    disable this in a production deployment.
    """
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing API key"
        )
