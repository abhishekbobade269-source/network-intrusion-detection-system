"""Drives the actual `nids` CLI entrypoint (`nids.cli.app`) via Typer's
CliRunner — argument parsing, the `train`/`replay` commands wired to their
real implementations, and console output — rather than calling the
underlying functions directly as the other test modules do.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from nids.cli import app

runner = CliRunner()
FIXTURE = Path(__file__).parents[1] / "fixtures" / "demo_traffic.pcap"


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("serve", "train", "replay", "sniff"):
        assert command in result.output


def test_train_command_trains_and_saves_a_model(tmp_path: Path) -> None:
    model_path = tmp_path / "cli_model.joblib"

    result = runner.invoke(
        app,
        [
            "train",
            "--dataset",
            "synthetic",
            "--out",
            str(model_path),
            "--n-estimators",
            "10",
        ],
    )

    assert result.exit_code == 0, result.output
    assert model_path.exists()
    assert "Saved model to" in result.output


def test_train_command_rejects_unknown_dataset() -> None:
    result = runner.invoke(app, ["train", "--dataset", "not-a-real-dataset"])
    assert result.exit_code != 0


def test_replay_command_runs_against_the_demo_fixture(tmp_path: Path) -> None:
    if not FIXTURE.exists():
        import pytest

        pytest.skip(f"demo fixture missing — run scripts/generate_demo_pcap.py ({FIXTURE})")

    # ml_enabled defaults to True but no model has been trained in this
    # tmp working directory — disable it so this test only exercises the
    # signature path, matching what a fresh clone without a trained model
    # would see.
    result = runner.invoke(app, ["replay", str(FIXTURE), "--no-ml-enabled"])

    assert result.exit_code == 0, result.output
    assert "ALERT" in result.output
    assert "TCP NULL scan probe" in result.output
    assert "Session summary" in result.output


def test_replay_command_rejects_missing_pcap_path() -> None:
    result = runner.invoke(app, ["replay", "does/not/exist.pcap"])
    assert result.exit_code != 0
