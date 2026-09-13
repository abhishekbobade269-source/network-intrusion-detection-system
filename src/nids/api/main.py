"""FastAPI application factory.

Wires together config, logging, the rule engine, the ML scorer, the
detection engine, the alert store/notifier, and the websocket broadcaster
into one process — this is the "production" entrypoint
(`uvicorn nids.api.main:app`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from nids.alerts.notifier import AlertNotifier
from nids.alerts.schemas import AlertCreate
from nids.api.limiter import limiter
from nids.api.routes import alerts as alerts_routes
from nids.api.routes import stats as stats_routes
from nids.api.routes import system as system_routes
from nids.api.routes import ws as ws_routes
from nids.api.state import AppState
from nids.common import Severity
from nids.config import get_settings
from nids.db.base import Base
from nids.db.session import get_sessionmaker, init_engine
from nids.detection.pipeline import Detection, DetectionEngine
from nids.flows.flow_tracker import FlowTracker
from nids.logging_config import configure_logging, get_logger
from nids.ml.predict import AnomalyScorer
from nids.rules.engine import RuleEngine
from nids.rules.loader import load_rules
from nids.rules.scan_detector import PortScanDetector

logger = get_logger(__name__)


def _build_engine() -> DetectionEngine:
    settings = get_settings()
    rules = load_rules(settings.rules_dir)
    scorer = AnomalyScorer(settings.ml_model_path, threshold=settings.ml_anomaly_threshold)
    if settings.ml_enabled:
        scorer.load()
    return DetectionEngine(
        rule_engine=RuleEngine(rules),
        scan_detector=PortScanDetector(),
        anomaly_scorer=scorer,
        flow_tracker=FlowTracker(
            idle_timeout_s=settings.flow_idle_timeout_s,
            active_timeout_s=settings.flow_active_timeout_s,
        ),
        ml_enabled=settings.ml_enabled,
    )


async def _noop_on_detection(_detection: Detection) -> None:
    """Placeholder wired into `AppState` before the real callback (which
    needs `state` itself, hence the two-step construction) is attached.
    """


def _make_on_detection(state: AppState):
    sessionmaker = get_sessionmaker()

    async def on_detection(detection: Detection) -> None:
        record, finding = detection.record, detection.finding
        try:
            async with sessionmaker() as session:
                from nids.alerts.store import (
                    AlertStore,  # local import avoids a cycle at module load
                )

                store = AlertStore(session)
                await store.create(
                    AlertCreate.from_finding(
                        finding,
                        src_ip=record.src_ip,
                        dst_ip=record.dst_ip,
                        src_port=record.src_port,
                        dst_port=record.dst_port,
                        protocol=int(record.protocol),
                    )
                )
        except Exception:  # noqa: BLE001 — a storage hiccup must not kill the capture loop
            logger.exception("alert.persist_failed", rule_id=finding.rule_id)

        await state.ws_manager.broadcast_detection(detection)
        await state.notifier.notify(
            rule_id=finding.rule_id,
            name=finding.name,
            severity=finding.severity,
            description=finding.description,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
        )

    return on_detection


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    settings = get_settings()
    logger.info("app.startup", environment=settings.environment)

    engine = init_engine()
    if not settings.is_production:
        # Dev/test convenience only — production deployments should manage
        # schema via Alembic (`alembic upgrade head`), not implicit DDL. If
        # no database is reachable (e.g. running the API standalone to hit
        # non-DB endpoints, or unit-ish tests), log and keep serving instead
        # of refusing to start — DB-backed routes will simply error until a
        # database is available.
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        except Exception:  # noqa: BLE001 — startup DB probe, not a hard dependency here
            logger.warning("app.startup_db_unreachable", database_url=settings.database_url)

    detection_engine = _build_engine()
    notifier = AlertNotifier(settings.alert_webhook_url, Severity(settings.alert_min_severity))
    state = AppState(engine=detection_engine, notifier=notifier, on_detection=_noop_on_detection)
    state.on_detection = _make_on_detection(state)
    app.state.nids = state

    yield

    if state.runner is not None:
        state.runner.stop()
    await engine.dispose()
    logger.info("app.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="NIDS — Hybrid Network Intrusion Detection System",
        description=(
            "Signature + ML-anomaly hybrid intrusion detection: live capture "
            "or pcap replay, flow-based feature extraction, YAML signature "
            "rules, an Isolation-Forest anomaly model, and a PostgreSQL-backed "
            "alert API with a live websocket feed."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(alerts_routes.router)
    app.include_router(stats_routes.router)
    app.include_router(system_routes.router)
    app.include_router(ws_routes.router)

    @app.get("/", tags=["system"])
    async def root() -> dict:
        return {"name": "nids", "docs": "/docs", "health": "/system/health"}

    return app


app = create_app()
