# NIDS — Hybrid Network Intrusion Detection System

A production-shaped, hybrid **signature + ML-anomaly** network intrusion
detection system: live packet capture or offline pcap/dataset replay →
per-flow feature extraction → YAML signature rules + an Isolation-Forest
anomaly model → a PostgreSQL-backed alert API with a live websocket feed
and a lightweight dashboard.

Built as a portfolio project — this expands the one-line "Network
Intrusion Detection System" academic project into something that runs
end-to-end and is deployable, not a toy script.

## Why hybrid?

- **Signatures** (`src/nids/rules/`) catch known attack *shapes* deterministically
  and explainably — port scans (SYN/NULL/FIN/XMAS), SYN/ICMP/UDP floods,
  suspected exfiltration, suspected C2 beaconing — with zero training data
  and zero false-negative risk for the patterns they cover.
- **ML anomaly detection** (`src/nids/ml/`) is trained **only on benign
  traffic** (unsupervised Isolation Forest) so it can flag flows that don't
  look like *anything* normal — including attacks nobody wrote a rule for
  yet. It's a complement to the rule engine, not a replacement.

Both detectors score the same flow-level feature vector and both emit the
same `Finding` type, so the alerting/storage/notification layer doesn't
care which one fired.

## Architecture

```
┌──────────────┐     ┌────────────┐     ┌──────────────────────────┐
│ Live NIC      │     │ pcap file  │     │ Public dataset            │
│ (scapy sniff) │     │ replay     │     │ (CICIDS2017, offline)     │
└──────┬───────┘     └─────┬──────┘     └─────────┬─────────────────┘
       │                    │                       │ (training only)
       ▼                    ▼                       ▼
  ┌─────────────────────────────────┐        ┌───────────────────┐
  │ Packet normalization (Packet)   │        │ nids.ml.train      │
  └───────────────┬─────────────────┘        │ IsolationForest    │
                   ▼                          │ + StandardScaler   │
        ┌─────────────────────┐               └─────────┬─────────┘
        │ FlowTracker         │                          │ joblib
        │ (flow aggregation,  │                          ▼
        │  feature vectors)   │               ┌─────────────────────┐
        └──────────┬──────────┘               │ AnomalyScorer       │
                   ▼                          │ (loads the artifact) │
        ┌─────────────────────┐               └──────────┬──────────┘
        │ DetectionEngine     │◄─────────────────────────┘
        │  • RuleEngine (YAML)│
        │  • PortScanDetector │
        │  • AnomalyScorer    │
        └──────────┬──────────┘
                   ▼ Finding(s)
        ┌─────────────────────┐        ┌─────────────────┐
        │ AlertStore (Postgres)│──────▶│ FastAPI REST API │
        │ AlertNotifier (hook) │       │ + /ws/alerts feed│
        └─────────────────────┘        └────────┬─────────┘
                                                   ▼
                                        ┌────────────────────┐
                                        │ dashboard/ (Vite)   │
                                        └────────────────────┘
```

See `docs/architecture.md` for the detailed walkthrough, `docs/model_card.md`
for the ML model's training data/limitations, and `docs/threat_model.md` for
what this system does and does not protect against.

## Quickstart

```bash
# 1. Backend — API + Postgres
cp .env.example .env
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

docker compose up -d postgres
alembic upgrade head

# 2. Train the (demo) anomaly model — no external dataset needed
nids train --dataset synthetic --out models/anomaly_model.joblib

# 3. Run the API
nids serve   # http://localhost:8000/docs

# 4. Try detection against a pcap (no live capture / root needed)
nids replay path/to/some.pcap
```

Live capture (`nids sniff --iface eth0`, or `POST /system/capture/start`
with `{"mode": "live", "iface": "eth0"}`) needs elevated privileges
(root / `setcap cap_net_raw,cap_net_admin=eip $(which python)` on Linux,
Npcap on Windows) — see `docs/architecture.md#live-capture-privileges`.

### Train on CICIDS2017 instead of the synthetic demo set

```bash
# Download the daily CSVs yourself from https://www.unb.ca/cic/datasets/ids-2017.html
nids train --dataset cicids2017 \
  --cicids-csv data/raw/Monday-WorkingHours.pcap_ISCX.csv \
  --cicids-csv data/raw/Tuesday-WorkingHours.pcap_ISCX.csv
```

## Full stack via Docker Compose

```bash
docker compose up --build
```

Brings up Postgres, runs Alembic migrations, starts the API on
`http://localhost:8000` (with `NET_RAW`/`NET_ADMIN` plus a `setcap` on the
interpreter — see `docker-compose.yml`/`Dockerfile` — so live capture on
the container's own interface genuinely works, not just pcap replay), and
the dashboard on `http://localhost:5173`.

**No `NIDS_API_KEY` set?** Capture start/stop and acknowledging alerts
need one — rather than leaving those endpoints open, the API generates a
random key at startup and logs it once:
`docker compose logs api | grep generated_api_key`. Set `NIDS_API_KEY`
yourself (in `docker-compose.yml` or your `.env`) for a key that survives
a restart; paste whichever one you're using into the dashboard's
"Capture control" panel.

## Project layout

```
src/nids/
  capture/     live sniffer (scapy) + pcap replay -> normalized Packet
  flows/       packet -> bidirectional flow aggregation -> feature vectors
  rules/       YAML signature engine + stateful port/host-scan detector
  ml/          feature schema, dataset loaders, training, live scoring
  detection/   sync detection core (pipeline.py) + async runner (runner.py)
  alerts/      ORM model, Pydantic schemas, Postgres store, webhook notifier
  db/          async SQLAlchemy engine/session
  api/         FastAPI app: REST + websocket + capture control
  cli.py       `nids serve|train|replay|sniff`
migrations/    Alembic
dashboard/     Vite + React + TS live alert dashboard
tests/         pytest unit + integration suite
docs/          architecture, threat model, model card
```

## Development

```bash
pip install -e ".[dev]"
pre-commit install

ruff check . && ruff format --check .
mypy src
bandit -c pyproject.toml -r src
pytest                      # DB-backed tests auto-skip if Postgres isn't running
```

Or just `make check` (see `Makefile` — mirrors CI in one command; `make train`,
`make replay`, `make serve` wrap the common `nids` invocations too).

CI (`.github/workflows/nids-ci.yml`) runs lint, type-check, security scan,
the test suite against a real Postgres service container, and a Docker
build on every push and every pull request.

## Status / scope

This is a real, runnable hybrid IDS, not a production SOC deployment out of
the box: see `docs/threat_model.md` for explicit non-goals (encrypted
traffic content inspection, distributed/multi-sensor correlation, active
response). Treat the ML model's headline metrics as demo-data metrics
until it's retrained on CICIDS2017 or your own labeled traffic — see
`docs/model_card.md`.
