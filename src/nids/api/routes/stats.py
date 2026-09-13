from __future__ import annotations

from fastapi import APIRouter, Depends

from nids.alerts.schemas import AlertStats
from nids.alerts.store import AlertStore
from nids.api.deps import get_alert_store, get_app_state
from nids.api.state import AppState

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=AlertStats)
async def get_alert_stats(store: AlertStore = Depends(get_alert_store)) -> AlertStats:
    return await store.stats()


@router.get("/engine")
async def get_engine_stats(state: AppState = Depends(get_app_state)) -> dict:
    return {
        "packets_seen": state.engine.packets_seen,
        "flows_evaluated": state.engine.flows_evaluated,
        "active_flows": state.engine.flow_tracker.active_flow_count,
        "ml_enabled": state.engine.ml_enabled,
        "is_capturing": state.is_capturing,
        "capture_mode": state.capture_mode,
        "capture_source": state.capture_source,
    }
