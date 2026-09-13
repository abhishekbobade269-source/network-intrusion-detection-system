# Progress

## Repo

- **Live at:** https://github.com/abhishekbobade269-source/network-intrusion-detection-system
- Public, branch `master`. Every commit authored as
  `Abhishek Bobade <abhishekbobade269@gmail.com>` only — verified against
  the GitHub API, no other name/email or AI-attribution anywhere in the
  history or tracked content.
- **CI is green.** `.github/workflows/nids-ci.yml` has run twice on
  GitHub (lint, mypy, bandit, the test suite against a real Postgres
  service container, a Docker build) — both `completed`/`success`.

## What's done and genuinely verified (not just written)

- **Full detection pipeline** — capture (live NIC / pcap replay) → flow
  aggregation → YAML signature rules + stateful port-scan detector +
  Isolation Forest anomaly model → alerting (Postgres store, webhook,
  rate-limited FastAPI + websocket API) → Vite/React dashboard.
- **The actual `docker compose up --build` stack was run for real** —
  postgres, migrations, the API, the dashboard — not just built. Verified
  past "the containers start": `POST /system/capture/start` replayed the
  demo pcap *through the running container*, persisted alerts came back
  over `GET /alerts`, and the dashboard rendered them live in a real
  browser (console clean, live-feed badge connected, 56 real alerts, all
  three detector types represented) — screenshotted, not assumed.
- 60 tests pass locally against a real (throwaway) Postgres instance, 0
  skipped, 91%+ coverage. `ruff`, `mypy`, `bandit` all clean.

## Real bugs found and fixed (all six, by actually running things — not by re-reading code)

1. First packet of every capture session silently dropped (scapy layer-
   binding registered one packet too late).
2. `/ws/alerts` crashed on every websocket connection attempt (dependency
   typed for an HTTP `Request`, which doesn't exist in a websocket scope).
3. `load_cicids2017` raised `KeyError` on any real input (never computed
   `total_packets`/`total_bytes`).
4. The test suite itself was flaky by construction (a `@lru_cache`'d
   async DB engine bound to whichever pytest-asyncio event loop ran
   first).
5. **The container loaded zero signature rules, silently.**
   `Settings.rules_dir`'s default assumed a source-tree layout that's
   only true for an editable install, not the real wheel install the
   Dockerfile actually does.
6. **The container couldn't reach Postgres either, silently.** The
   compose file's `network_mode: host` on the API service broke both
   `localhost:8000` reachability *and* the `postgres` hostname's DNS
   resolution on Docker Desktop — invisible at startup because
   `NIDS_ENVIRONMENT=production` skips the dev-mode DB probe that would
   have logged it.

Bugs 5 and 6 were found *this session*, specifically because Docker
actually got run instead of just written — full detail (and why each fix
is the right one, not a workaround) is in `docs/architecture.md`'s "Bugs
this project's own tests caught" section. `tests/unit/test_config.py`
guards bug 5 against ever silently coming back.

## Still open

- **Never trained on real CICIDS2017 data** — the loader is test-verified
  against real-shaped CSVs, but the actual multi-GB dataset was never
  downloaded (size/license — see `docs/model_card.md`). Shipped/tested
  model is still the synthetic one.
- **Live NIC capture untested end-to-end** — no Npcap/root capture rights
  available in any environment used so far. Everything up to the actual
  sniff (warm-up, normalization, the "unavailable" guard clause, and now
  the container's own `can_capture_live() == true` inside Linux) is
  covered; a real NIC was never attached.
- **No LICENSE file** — deliberately left as your call, not added
  unilaterally.

## To resume

```bash
cd "IDS(Intrusion Detection system)"
pip install -e ".[dev]"        # if the venv needs recreating
nids train --dataset synthetic --out models/anomaly_model.joblib
make check                     # mirrors CI
make compose-up                # full stack incl. dashboard, now verified working
```

No servers, databases, or containers are left running — the
docker-compose stack used for verification was torn down
(`docker compose down -v`) before this note was written.
