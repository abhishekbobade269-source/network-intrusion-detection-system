# Progress

Updated after a second work session that closed out the items the first
one had left open. Kept as a running log rather than deleted, since
"what's actually verified vs. assumed" is exactly the kind of thing that
goes stale silently otherwise.

## Done

- **Capture** — live NIC sniffing (`nids.capture.sniffer.LiveSniffer`, scapy
  `AsyncSniffer`) and offline pcap replay (`nids.capture.pcap_reader`), both
  normalized into one `Packet` model (`nids.capture.packet`).
- **Flows** — bidirectional flow aggregation with Welford's online stats
  (`nids.flows`), producing the 26-feature vector both detectors share.
- **Signature detection** — YAML rule engine with rules for TCP
  NULL/FIN/XMAS/half-open scans, SYN/ICMP/UDP floods, suspected
  exfiltration, and suspected C2 beaconing, plus a stateful cross-flow
  port/host-scan detector.
- **ML anomaly detection** — Isolation Forest trained on benign-only
  traffic; synthetic dataset generator for a dependency-free pipeline;
  CICIDS2017 CSV loader for real accuracy (see "still open" below).
- **Alerting** — async detection runner, PostgreSQL-backed alert store
  (SQLAlchemy 2.0 + Alembic), a webhook notifier, and a FastAPI REST +
  websocket API with capture start/stop control.
- **API hardening** — per-IP rate limiting (`nids.api.limiter`, slowapi) on
  every write/control endpoint (`/system/capture/*`,
  `/alerts/{id}/acknowledge`), on top of the existing API-key gate.
- **Dashboard** — Vite + React + TS live alert feed with capture controls.
- **Ops/tooling** — Dockerfiles, docker-compose, GitHub Actions CI,
  pyproject with ruff/mypy/bandit/pytest, pre-commit, Makefile.
- **Docs** — README, architecture (now including a section on the actual
  bugs this project's own tests caught), threat model, model card.
- **Its own independent git repo.** This folder was originally committed
  into the shared Abhi_Portfolio monorepo (it never got its own `.git`, so
  `git add`/`git commit` walked up to the parent's); a sibling session
  building another portfolio project caught this, the user confirmed each
  project gets its own repo, and this folder now has a fresh, independent
  history (`git init -b master`, one root commit) instead.

## Verified this session (previously only "written, not run")

- **A real PostgreSQL instance, not just auto-skip.** No Postgres was
  running last time; this session initialized a throwaway local cluster
  (`initdb`/`pg_ctl`, trust auth, its own port, torn down after) and ran
  the full suite against it for real — migrations included.
- **The full HTTP control-plane path.** `POST /system/capture/start` (pcap
  mode) → real pcap replay → real persisted Postgres rows → `GET /alerts`
  returning them — the one path that exercises the API's actual
  `on_detection` wiring, not a hand-rolled equivalent
  (`tests/integration/test_alert_persistence.py`,
  `test_api.py::test_capture_start_replays_pcap_and_alerts_are_queryable`).
- **A real ASGI websocket handshake against `/ws/alerts`** — and it caught
  a genuine bug in the process (below).
- **The CICIDS2017 loader against real-shaped data** — and it also caught
  a genuine bug (below).

## Bugs found and fixed by actually running things

Real ones, not the kind you get from re-reading your own code:

1. **First packet of every capture session silently dropped.** Scapy's
   Ether→IP layer binding was registered lazily (inside the per-packet
   parser), one packet too late for the very first packet of any session.
   Fixed with `nids.capture._scapy_parse.warm_up_scapy_layers()`, called
   before any reading starts.
2. **`/ws/alerts` crashed on every connection attempt.** Its dependency
   was typed for an HTTP `Request`, which doesn't exist in a websocket
   scope. Fixed with a dedicated `get_app_state_ws` dependency.
3. **`load_cicids2017` raised `KeyError` on any real CICIDS2017 input.**
   It never computed `total_packets`/`total_bytes` (CICFlowMeter only has
   the forward/backward halves), so the cleanup step crashed looking for
   columns that were never created. Fixed by deriving both totals right
   after the column rename.
4. **The test suite itself was flaky by construction.** The app's
   `@lru_cache`'d async DB engine (correct for a long-running server) got
   bound to whichever event loop happened to run first under
   pytest-asyncio's default per-test-function loop, so later DB tests
   intermittently failed cleaning up connections against an already-closed
   loop. Fixed in `pyproject.toml` (session-scoped test/fixture event
   loops), not application code.

All four are written up in more detail in `docs/architecture.md`'s "Bugs
this project's own tests caught" section.

## Current numbers

- 60 tests pass (0 skipped, run against a real Postgres instance).
- 91% overall coverage (`pytest`'s own report — see the low points below).
- `ruff check .`, `ruff format --check .`, `mypy src`, and
  `bandit -c pyproject.toml -r src` are all clean.

## Still open (honestly, not just "future work" filler)

- **Never trained on real CICIDS2017 data.** The loader is now
  test-verified against real-shaped CSVs, but no actual multi-GB dataset
  was downloaded in this environment (size/license reasons — see
  `docs/model_card.md`) — the shipped model is still the synthetic one.
- **Live NIC capture is still untested end to end.** This dev environment
  has no Npcap/root capture rights. Pcap replay and the live-capture *code
  path minus the actual sniff* (warm-up, normalization, the "unavailable"
  guard clause) are covered; a real NIC was never attached.
- **`nids.capture.sniffer` is at 29% coverage** for the same reason — the
  parts that need a real interface can't be exercised here.
- **CI has still never actually run on GitHub** — it's now correctly
  positioned in this repo's own `.github/workflows/`, but nothing has been
  pushed to a GitHub remote from this environment.
- No LICENSE file — still a deliberate call for you to make, not
  something to add unilaterally.

## To pick this back up

```bash
cd "IDS(Intrusion Detection system)"
pip install -e ".[dev]"
nids train --dataset synthetic --out models/anomaly_model.joblib
nids replay tests/fixtures/demo_traffic.pcap   # or: make check / make compose-up
```
