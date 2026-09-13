from __future__ import annotations

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from nids.api.deps import get_app_state_ws
from nids.api.state import AppState

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def alerts_feed(websocket: WebSocket, state: AppState = Depends(get_app_state_ws)) -> None:
    await state.ws_manager.connect(websocket)
    try:
        while True:
            # Dashboard doesn't send anything meaningful; this just detects
            # the disconnect so we can clean the connection up.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await state.ws_manager.disconnect(websocket)
