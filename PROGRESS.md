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

## Dashboard demo mode (recruiter-facing, no backend required)

Added a `VITE_DEMO_MODE` build mode so the dashboard can run standalone —
no FastAPI, no Postgres, no websocket — for sharing the UI without
standing up the full stack:

- `dashboard/src/demoStore.ts` / `demoFixtures.ts`: an in-memory fake
  backend seeded with alert shapes the real detectors actually produce
  (port scan, ICMP flood, SYN flood, exfiltration, C2 beaconing, ML
  anomaly), plus a simulated live feed ticking every 4s so the "live"
  view isn't static.
- `api.ts`, `CaptureControl.tsx`, `useAlertsFeed.ts` branch on
  `DEMO_MODE` to read/write that store instead of hitting the network;
  the rest of the app (AlertsTable, StatsPanel, the connection badge)
  is unmodified and can't tell the difference.
- A visible "DEMO" banner links back to the real repo so it's never
  mistaken for a live feed.
- `npm run build:demo` (uses `.env.demo`) builds it to `dashboard/dist-demo/`,
  gitignored like the regular `dist/` — it's a build artifact, rebuilt
  on demand, not committed.
- Also fixed `npm run lint` scope (`oxlint src` instead of bare
  `oxlint`) — previously it swept up whatever was sitting in `dist*/`
  too, including minified build output.

## Landing → Login → Dashboard flow (demo mode only)

Reworked the demo build into a real three-screen product flow instead of
dropping a visitor straight on the alerts table, with its own visual
identity (deliberately not reusing the portfolio site's dark+green
network-graph look — an instrument-panel read instead: deep indigo,
antique brass as the primary signal color, a cool teal counter-signal,
Fraunces/Work Sans/IBM Plex Mono):

- `pages/Landing.tsx`: hero with an animated canvas "signal monitor"
  (`components/SignalScope.tsx` — a self-contained oscilloscope/radar
  generative graphic, standing in for stock/AI imagery there's no tool
  here to generate), a real 4-step detection pipeline, a 3-card feature
  grid, and a footer link back to the portfolio's `/work/nids` case
  study — the actual "connect this to my portfolio" link.
- `pages/Login.tsx`: a decorative access gate (`demoAuth.ts`) — there is
  still no real backend behind demo mode, so it's honest about that in
  its own copy, but it looks and behaves like a real login (a fake
  verify delay, a session-scoped gate on `/dashboard`, a "skip" escape
  hatch).
- `pages/Dashboard.tsx`: the former `App.tsx` content, restyled to the
  same tokens, with Framer Motion added throughout (panel stagger-in,
  count-up stat numbers, animated severity bars, live alert rows
  animating in via `AnimatePresence`).
- Installed `framer-motion` and `react-router-dom` (`HashRouter`, so the
  static demo bundle needs no server-side rewrite rule to serve
  `/login` / `/dashboard` on a direct load).
- Outside demo mode this routing is skipped entirely — `App.tsx` renders
  `Dashboard` directly, so a real `docker compose up` deployment is
  unaffected and still opens straight on the live alerts view.
- Verified: `tsc -b`, `oxlint src`, and both `npm run build` and
  `npm run build:demo` are clean.

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
