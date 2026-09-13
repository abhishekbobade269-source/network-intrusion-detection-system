from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from nids.alerts.schemas import AlertOut
from nids.alerts.store import AlertStore
from nids.api.deps import get_alert_store, require_api_key
from nids.api.limiter import CONTROL_RATE_LIMIT, limiter

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    limit: int = Query(default=100, le=1000, ge=1),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    detector: str | None = Query(default=None),
    store: AlertStore = Depends(get_alert_store),
) -> list[AlertOut]:
    rows = await store.list(
        limit=limit, offset=offset, severity=severity, src_ip=src_ip, detector=detector
    )
    return [AlertOut.model_validate(r) for r in rows]


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: str, store: AlertStore = Depends(get_alert_store)) -> AlertOut:
    row = await store.get(alert_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return AlertOut.model_validate(row)


@router.post(
    "/{alert_id}/acknowledge",
    response_model=AlertOut,
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(CONTROL_RATE_LIMIT)
async def acknowledge_alert(
    request: Request, alert_id: str, store: AlertStore = Depends(get_alert_store)
) -> AlertOut:
    row = await store.acknowledge(alert_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return AlertOut.model_validate(row)
