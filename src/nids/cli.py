"""`nids` command-line entrypoint.

nids serve                     # run the API (uvicorn), the "production" path
nids train --dataset synthetic # train the anomaly model
nids replay capture.pcap       # replay a pcap through detection, print findings
nids sniff --iface eth0        # live capture through detection, print findings
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from nids.config import get_settings
from nids.detection.pipeline import Detection, DetectionEngine
from nids.detection.runner import DetectionRunner
from nids.flows.flow_tracker import FlowTracker
from nids.logging_config import configure_logging
from nids.ml import train as train_module
from nids.ml.predict import AnomalyScorer
from nids.rules.engine import RuleEngine
from nids.rules.loader import load_rules
from nids.rules.scan_detector import PortScanDetector

app = typer.Typer(add_completion=False, help="NIDS — hybrid signature + ML intrusion detection.")
# Mounted directly (not as a sub-typer) so it's `nids train --dataset ...`
# rather than the redundant `nids train train ...`.
app.command(name="train")(train_module.train)
console = Console()


def _build_standalone_engine(ml_enabled: bool) -> DetectionEngine:
    settings = get_settings()
    rules = load_rules(settings.rules_dir)
    scorer = AnomalyScorer(settings.ml_model_path, threshold=settings.ml_anomaly_threshold)
    if ml_enabled:
        scorer.load()
    return DetectionEngine(
        rule_engine=RuleEngine(rules),
        scan_detector=PortScanDetector(),
        anomaly_scorer=scorer,
        flow_tracker=FlowTracker(
            idle_timeout_s=settings.flow_idle_timeout_s,
            active_timeout_s=settings.flow_active_timeout_s,
        ),
        ml_enabled=ml_enabled,
    )


async def _print_on_detection(detection: Detection) -> None:
    f = detection.finding
    r = detection.record
    console.print(
        f"[bold red]ALERT[/] [{f.severity.value.upper()}] {f.name} "
        f"({f.detector.value}, conf={f.confidence:.2f}) "
        f"{r.src_ip}:{r.src_port} -> {r.dst_ip}:{r.dst_port} — {f.description}"
    )


@app.command()
def serve(
    host: str | None = typer.Option(None),
    port: int | None = typer.Option(None),
    reload: bool = typer.Option(False),
) -> None:
    """Run the FastAPI app (the API, alert store, dashboard websocket, and
    on-demand capture control) — the production entrypoint.
    """
    settings = get_settings()
    uvicorn.run(
        "nids.api.main:app",
        host=host or settings.api_host,
        port=port or settings.api_port,
        reload=reload,
    )


@app.command()
def replay(
    pcap_path: Path = typer.Argument(..., exists=True),
    ml_enabled: bool = typer.Option(True, help="Score flows with the trained anomaly model too."),
) -> None:
    """Replay a pcap file through the full detection pipeline, printing each finding."""
    configure_logging()
    engine = _build_standalone_engine(ml_enabled)
    runner = DetectionRunner(engine, on_detection=_print_on_detection)
    asyncio.run(runner.run_pcap(str(pcap_path)))
    _print_summary(engine)


@app.command()
def sniff(
    iface: str | None = typer.Option(None, help="Network interface; omit to let scapy pick one."),
    bpf_filter: str = typer.Option("ip or ip6"),
    ml_enabled: bool = typer.Option(True),
) -> None:
    """Live-capture on a NIC through the full detection pipeline (requires
    elevated privileges), printing each finding until Ctrl+C.
    """
    configure_logging()
    engine = _build_standalone_engine(ml_enabled)
    runner = DetectionRunner(engine, on_detection=_print_on_detection)
    try:
        asyncio.run(runner.run_live(iface, bpf_filter))
    except KeyboardInterrupt:
        runner.stop()
    _print_summary(engine)


def _print_summary(engine: DetectionEngine) -> None:
    table = Table(title="Session summary")
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("packets seen", str(engine.packets_seen))
    table.add_row("flows evaluated", str(engine.flows_evaluated))
    console.print(table)


if __name__ == "__main__":
    app()
