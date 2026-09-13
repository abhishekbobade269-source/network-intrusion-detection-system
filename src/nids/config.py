"""Central configuration.

All runtime configuration is sourced from environment variables (with sane
local-dev defaults) via pydantic-settings, following 12-factor conventions.
Never hardcode secrets — see .env.example for the full variable list.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="NIDS_",
        case_sensitive=False,
        extra="ignore",
    )

    # --- App metadata ---
    app_name: str = "nids"
    environment: str = Field(default="development")  # development | staging | production
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=False)

    # --- API ---
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    api_key: str | None = Field(default=None, description="Static API key for write endpoints")

    # --- Database ---
    database_url: str = Field(
        default="postgresql+asyncpg://nids:nids@localhost:5432/nids",
        description="SQLAlchemy async DSN for the alert/flow store",
    )
    database_echo: bool = Field(default=False)

    # --- Capture ---
    capture_interface: str | None = Field(
        default=None, description="NIC to sniff, e.g. eth0 / Wi-Fi. None = replay-only mode."
    )
    capture_bpf_filter: str = Field(default="ip or ip6")
    flow_idle_timeout_s: float = Field(default=15.0)
    flow_active_timeout_s: float = Field(default=120.0)

    # --- Detection ---
    rules_dir: Path = Field(default=PROJECT_ROOT / "src" / "nids" / "rules" / "definitions")
    ml_model_path: Path = Field(default=PROJECT_ROOT / "models" / "anomaly_model.joblib")
    ml_anomaly_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    ml_enabled: bool = Field(default=True)

    # --- Alerting ---
    alert_webhook_url: str | None = Field(default=None)
    alert_min_severity: str = Field(default="low")  # low | medium | high | critical

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — import this, not Settings() directly."""
    return Settings()
