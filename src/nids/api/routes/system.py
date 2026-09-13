from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator

from nids.api.deps import get_app_state, require_api_key
from nids.api.limiter import CONTROL_RATE_LIMIT, limiter
from nids.api.state import AppState
from nids.capture.sniffer import can_capture_live
from nids.config import get_settings
from nids.detection.runner import DetectionRunner
from nids.logging_config import get_logger

router = APIRouter(prefix="/system", tags=["system"])
logger = get_logger(__name__)


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/capabilities")
async def capabilities(state: AppState = Depends(get_app_state)) -> dict:
    return {
        "can_capture_live": can_capture_live(),
        "ml_model_loaded": state.engine.anomaly_scorer.is_loaded
        if state.engine.anomaly_scorer
        else False,
        "rules_loaded": len(state.engine.rule_engine.rules),
    }


class CaptureStartRequest(BaseModel):
    mode: Literal["live", "pcap"]
    iface: str | None = Field(default=None, description="Required when mode='live'")
    bpf_filter: str = "ip or ip6"
    pcap_path: str | None = Field(default=None, description="Required when mode='pcap'")

    @model_validator(mode="after")
    def _check_source(self) -> CaptureStartRequest:
        if self.mode == "pcap" and not self.pcap_path:
            raise ValueError("pcap_path is required when mode='pcap'")
        return self


@router.post("/capture/start", dependencies=[Depends(require_api_key)])
@limiter.limit(CONTROL_RATE_LIMIT)
async def start_capture(
    request: Request, body: CaptureStartRequest, state: AppState = Depends(get_app_state)
) -> dict:
    if state.is_capturing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="capture already running")

    if body.mode == "live" and not can_capture_live():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=(
                "live capture unavailable in this environment (no interfaces / missing privileges)"
            ),
        )

    # Catch the single most common failure (a typo'd/missing path) here,
    # synchronously, instead of letting it surface as a bare, uncaught
    # exception in the background capture thread minutes later — this
    # used to return 200 "started" for a pcap_path that could never work,
    # with the actual FileNotFoundError visible only as a raw Python
    # traceback in server logs, never to the caller. Doesn't cover every
    # failure mode (a truncated/corrupt pcap can still fail mid-stream),
    # but the common one is now an immediate, clear 400.
    if body.mode == "pcap" and not Path(body.pcap_path).is_file():  # type: ignore[arg-type]
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"pcap_path does not exist or is not a file: {body.pcap_path}",
        )

    settings = get_settings()
    state.runner = DetectionRunner(state.engine, on_detection=state.on_detection)
    state.capture_mode = body.mode
    state.capture_source = body.iface if body.mode == "live" else body.pcap_path

    if body.mode == "live":
        coro = state.runner.run_live(body.iface, body.bpf_filter or settings.capture_bpf_filter)
    else:
        assert body.pcap_path is not None
        coro = state.runner.run_pcap(body.pcap_path)

    state.runner_task = asyncio.create_task(coro, name="nids-detection-runner")
    logger.info("capture.started", mode=body.mode, source=state.capture_source)
    return {"status": "started", "mode": body.mode, "source": state.capture_source}


@router.post("/capture/stop", dependencies=[Depends(require_api_key)])
@limiter.limit(CONTROL_RATE_LIMIT)
async def stop_capture(request: Request, state: AppState = Depends(get_app_state)) -> dict:
    if not state.is_capturing or state.runner is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="capture is not running")
    state.runner.stop()
    if state.runner_task is not None:
        try:
            await asyncio.wait_for(state.runner_task, timeout=10.0)
        except TimeoutError:
            state.runner_task.cancel()
    logger.info("capture.stopped")
    return {"status": "stopped"}
