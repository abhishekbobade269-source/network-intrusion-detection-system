# Progress

## Repo

- **Live at:** https://github.com/abhishekbobade269-source/network-intrusion-detection-system
- Public, branch `master`. Every commit authored as
  `Abhishek Bobade <abhishekbobade269@gmail.com>` only — verified against
  the GitHub API.
- **CI is green** (lint, mypy, bandit, tests against a real Postgres
  service container, Docker build).

## What's done and genuinely verified

Full hybrid signature + ML anomaly-detection NIDS — live capture and pcap
replay, flow aggregation, YAML rules + a stateful port-scan detector, an
Isolation Forest anomaly model, a rate-limited FastAPI + websocket API
backed by PostgreSQL, and a Vite/React dashboard. Verified past "it
builds": `docker compose up --build` actually run, replay and **live
capture both** driven through the real running containers (see below),
alerts checked over the API, in the dashboard, in a real browser.

60+ tests pass locally against a real (throwaway) Postgres, 91%+
coverage. `ruff`, `mypy`, `bandit`, `pip-audit` all clean. Dashboard
builds and lints clean.

## Real bugs found and fixed — 11 total, all by actually running things

**Earlier sessions (1–6):** first-packet-loss in capture; `/ws/alerts`
crashing on every connection (websocket route depending on an HTTP
`Request`); `load_cicids2017` `KeyError` on real input; a flaky-by-
construction test suite (event-loop/cached-engine mismatch);
zero-signature-rules-loaded in the real Docker image (`rules_dir`
resolution broke under a wheel install); the API unreachable and unable
to resolve `postgres` under `network_mode: host` on Docker Desktop.

**This session, from an operator/recruiter/production review pass
(requested explicitly: confirm it runs cleanly, then check it from those
three angles and fix what's found):**

7. **Live capture in the container needed two more fixes, found by
   actually trying it** (a real port scan from a second container, not a
   review of the Dockerfile): `cap_add` alone is useless for a non-root
   process without file capabilities on the actual binary
   (`PermissionError`); the base image had no `libpcap`/`tcpdump`, which
   scapy needs to compile a BPF filter at all (`Scapy_Exception`). Fixed
   both — **live capture now genuinely works**, confirmed with a real
   `nc` port scan producing a real `HOST_PORT_SCAN` alert off live
   traffic, not replay.
8. **A production deployment with no `NIDS_API_KEY` — exactly what
   `docker-compose.yml` produces — left every control endpoint
   completely open.** Confirmed exploitable directly (`capture/stop`
   with zero credentials succeeded against the real container). Fixed
   fail-safe: generate and log a random key at startup instead of
   silently allowing everything.
9. **The DB password was logged in plain text** on a warning path.
   Fixed with a `database_url_masked` property; nothing logs the raw DSN
   anymore.
10. **`capture/start` said `200 "started"` for a pcap path that could
    never work**, the real failure only ever visible as a raw traceback
    in server logs. Fixed: the common case is now a synchronous `400`;
    anything failing later is caught, logged cleanly, and surfaced
    through `/stats/engine` and the dashboard instead of crashing a
    thread silently.
11. **The dashboard's container reported `unhealthy` forever** despite
    working correctly — its healthcheck's `wget http://localhost/` hit
    IPv6 first, nothing listens there, no IPv4 fallback. Fixed by
    hardcoding `127.0.0.1`.

Full writeup of all eleven is in `docs/architecture.md`'s "Bugs this
project's own tests caught" section. Every one of 7–11 has a regression
test, not just a manual fix.

## Still open

- **Never trained on real CICIDS2017 data** — loader is test-verified
  against real-shaped CSVs; the actual multi-GB dataset was never
  downloaded (size/license). Shipped model is still the synthetic one.
- **No LICENSE file** — deliberately left as your call.
- Live capture is now verified on the container's own (veth) interface;
  a real physical NIC on bare metal/a VM with Npcap or root was still
  never attempted, though the code path exercised is identical.

## To resume

```bash
cd "IDS(Intrusion Detection system)"
pip install -e ".[dev]"
nids train --dataset synthetic --out models/anomaly_model.joblib
make check          # mirrors CI
make compose-up      # full stack — now verified working, including live capture
```

No servers, databases, or containers left running — the full
docker-compose stack was torn down (`docker compose down -v`) before this
note was written, after every container reported healthy.
