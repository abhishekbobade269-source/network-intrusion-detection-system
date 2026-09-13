# Progress — where this stands

Session paused here at the user's request. This file is the handoff: what's
done, what's verified, and what's still open, so picking this back up
doesn't require re-deriving context from the code alone.

## Done

- **Capture** — live NIC sniffing (`nids.capture.sniffer.LiveSniffer`, scapy
  `AsyncSniffer`) and offline pcap replay (`nids.capture.pcap_reader`), both
  normalized into one `Packet` model (`nids.capture.packet`).
- **Flows** — bidirectional flow aggregation with Welford's online stats
  (`nids.flows`), producing the 26-feature vector both detectors share
  (`nids.ml.features.FEATURE_COLUMNS`).
- **Signature detection** — YAML rule engine (`nids.rules.engine`/`loader`)
  with rules for TCP NULL/FIN/XMAS/half-open scans, SYN/ICMP/UDP floods,
  suspected exfiltration, and suspected C2 beaconing
  (`src/nids/rules/definitions/*.yaml`), plus a stateful cross-flow
  port/host-scan detector (`nids.rules.scan_detector.PortScanDetector`).
- **ML anomaly detection** — Isolation Forest trained on benign-only
  traffic (`nids.ml.train`), scored live per-flow (`nids.ml.predict`).
  Synthetic dataset generator (`nids.ml.datasets.make_synthetic_dataset`)
  for a dependency-free pipeline; CICIDS2017 CSV loader
  (`load_cicids2017`) for real accuracy, not yet exercised against the
  real dataset (see Pending).
- **Alerting** — async detection runner (`nids.detection.runner`) driving
  the sync detection core (`nids.detection.pipeline`), PostgreSQL-backed
  alert store (SQLAlchemy 2.0 + Alembic, `nids.alerts`, `nids.db`), a
  webhook notifier, and a FastAPI REST + websocket API
  (`nids.api`) with capture start/stop control.
- **Dashboard** — Vite + React + TS live alert feed with capture controls
  (`dashboard/`), builds and lints clean.
- **Ops/tooling** — Dockerfiles (API + dashboard) and `docker-compose.yml`,
  GitHub Actions CI at the repo root (`.github/workflows/nids-ci.yml`,
  path-scoped to this folder — not yet pushed/run on GitHub, see
  Pending), pyproject with ruff/mypy/bandit/pytest config, pre-commit,
  Makefile.
- **Docs** — `README.md`, `docs/architecture.md`, `docs/threat_model.md`
  (explicit non-goals), `docs/model_card.md` (training-data caveats).

## Verified (not just written)

- 20 tests pass, 1 (DB-backed) auto-skips without a running Postgres —
  `pytest` from the project folder.
- `ruff check .`, `ruff format --check .`, `mypy src`, and
  `bandit -c pyproject.toml -r src` are all clean.
- Ran the real pipeline end-to-end: `nids train --dataset synthetic`, then
  `nids replay tests/fixtures/demo_traffic.pcap` — confirmed the NULL-scan
  signature, the cross-flow port-scan detector, the ICMP-flood signature,
  and the ML anomaly scorer all fire correctly, while the one legitimate
  handshake flow in that fixture stays clean on the signature side.
- Found and fixed a real bug in that process: the first packet of any
  capture session was silently mis-parsed as `Raw` because
  `scapy.layers.inet`'s `bind_layers` registration was happening lazily,
  one packet too late (`nids.capture._scapy_parse.warm_up_scapy_layers`,
  documented in `docs/architecture.md`).
- Two commits on `master`: the main build, and a small Makefile/
  `.dockerignore` hardening follow-up.

## Pending / not done

- **Never trained on real data.** The shipped/tested model only ever saw
  the synthetic dataset — its metrics are a pipeline-correctness check,
  not an accuracy claim (spelled out in `docs/model_card.md`). Training
  against CICIDS2017 needs the CSVs downloaded manually (license/size
  reasons) and `nids train --dataset cicids2017 --cicids-csv ...` run
  against them.
- **CI has never actually run.** `.github/workflows/nids-ci.yml` exists at
  the repo root and is written to trigger on pushes/PRs touching this
  folder, but nothing has been pushed to GitHub yet in this session — it
  hasn't executed even once. First push will be the first real signal on
  whether it's green.
- **No auth/rate-limiting hardening beyond the basic API-key gate.**
  `NIDS_API_KEY` gates write/control endpoints; read endpoints
  (`/alerts`, `/stats`, `/ws/alerts`) are open by design for a private
  network (see `docs/threat_model.md`). Don't expose this publicly as-is.
- **Live capture is untested end-to-end.** Pcap replay was verified for
  real; live NIC sniffing (`nids sniff`, `POST /system/capture/start`
  `{"mode":"live"}`) exercises the same normalization/detection code path
  but wasn't run against a live interface in this session (this dev
  machine has no Npcap/root capture rights available).
- **Test coverage is ~69% overall**, concentrated in the pure-logic layers
  (flows/rules/packet at 100%); the API routes, the async runner, and the
  websocket manager are comparatively thin on direct test coverage (they
  are exercised indirectly by the DB-gated integration tests, but see the
  next point).
- **The DB-backed integration test never actually ran** in this session —
  no local Postgres was available, so it auto-skipped every time; it's
  unverified beyond "the code compiles and the query shapes look right."
- **Dashboard has no test suite** — it type-checks, builds, and lints
  clean, but there's no unit/e2e test coverage for the React components or
  the websocket-reconnect hook.
- No LICENSE file was added (deliberately skipped — `pyproject.toml`
  declares `license = "MIT"` as package metadata, but a repo-level license
  decision belongs to you, not something to add unilaterally).

## To pick this back up

```bash
cd "IDS(Intrusion Detection system)"
pip install -e ".[dev]"
nids train --dataset synthetic --out models/anomaly_model.joblib
nids replay tests/fixtures/demo_traffic.pcap   # or: make check / make compose-up
```
