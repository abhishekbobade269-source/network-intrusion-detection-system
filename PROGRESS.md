# Progress

Handoff note before a system restart — everything below is committed and
pushed, so it survives the restart even though nothing is running locally
anymore. Pick up with the "To resume after restart" section at the bottom.

## Repo

- **Live at:** https://github.com/abhishekbobade269-source/network-intrusion-detection-system
- Public, branch `master`, 3 commits, all authored as
  `Abhishek Bobade <abhishekbobade269@gmail.com>` only (no other name/email
  or AI-attribution anywhere in the history or tracked content — verified
  directly against the GitHub API, not just locally).
- Local clone: `C:\Users\monsx\OneDrive\Documents\Abhi_Portfolio\IDS(Intrusion Detection system)`
  — this folder has its own independent git repo (not part of the
  Abhi_Portfolio monorepo it originally lived in; see "Repo history" below
  for why).

## What's done

- **Capture** — live NIC sniffing (`nids.capture.sniffer.LiveSniffer`, scapy
  `AsyncSniffer`) and offline pcap replay (`nids.capture.pcap_reader`), both
  normalized into one `Packet` model.
- **Flows** — bidirectional flow aggregation with Welford's online stats,
  producing the 26-feature vector both detectors share.
- **Signature detection** — YAML rule engine (port/host scans, floods,
  suspected exfiltration, suspected C2 beaconing) plus a stateful
  cross-flow port/host-scan detector.
- **ML anomaly detection** — Isolation Forest trained on benign-only
  traffic; synthetic dataset generator (no download needed) and a
  CICIDS2017 CSV loader for real accuracy (see "Still open").
- **Alerting** — async detection runner, PostgreSQL-backed alert store
  (SQLAlchemy 2.0 + Alembic), a webhook notifier, FastAPI REST + websocket
  API with capture start/stop control, per-IP rate limiting on every
  write/control endpoint.
- **Dashboard** — Vite + React + TS live alert feed with capture controls.
- **Ops/tooling** — Dockerfiles, docker-compose, GitHub Actions CI
  (`.github/workflows/nids-ci.yml`, in this repo's own root now), pyproject
  with ruff/mypy/bandit/pytest, pre-commit, Makefile.
- **Docs** — README, `docs/architecture.md` (includes a section listing
  the real bugs this project's own tests caught, and why), `docs/threat_model.md`,
  `docs/model_card.md`.
- **Test numbers** — 60 tests pass (0 skipped, verified against a real,
  throwaway local Postgres instance — since torn down), 91% coverage.
  `ruff check .`, `ruff format --check .`, `mypy src`, and
  `bandit -c pyproject.toml -r src` all clean.

## Real bugs found and fixed (not just written — caught by actually running things)

1. First packet of every capture session was silently dropped (scapy's
   Ether→IP layer binding registered one packet too late). Fixed with
   `nids.capture._scapy_parse.warm_up_scapy_layers()`.
2. `/ws/alerts` crashed on every websocket connection attempt (a
   dependency typed for an HTTP `Request`, which doesn't exist in a
   websocket scope). Fixed with a dedicated `get_app_state_ws` dependency.
3. `load_cicids2017` raised `KeyError` on any real input — never computed
   `total_packets`/`total_bytes`. Fixed by deriving both from the
   forward/backward columns.
4. The test suite itself was flaky by construction (the app's
   `@lru_cache`'d async DB engine got bound to whichever pytest-asyncio
   event loop ran first). Fixed in `pyproject.toml` (session-scoped test
   loops), not application code.

Full detail on all four is in `docs/architecture.md`'s "Bugs this
project's own tests caught" section.

## Repo history (why there was a rewrite)

This folder was originally committed into the shared Abhi_Portfolio
monorepo by mistake (it never got its own `.git`, so `git commit` walked
up to the parent repo's). A sibling Claude session working on another
portfolio project caught this; the user confirmed each project gets its
own repo, so this folder got `git init` fresh. Those first commits then
carried the identity of the person operating Claude Code that day, not
Abhishek's — per an explicit request, that history was rewritten
(`git filter-branch`, then old objects fully purged with `reflog expire`
+ `gc --prune=now`) so every commit shows only Abhishek Bobade's name and
email, with no AI co-author line. This is *only* safe to do because the
repo was brand new with no other collaborators/clones — don't rewrite
history on a repo anyone else has already pulled.

## Still open

- **Never trained on real CICIDS2017 data.** The loader is test-verified
  against real-shaped CSVs, but no actual multi-GB dataset was downloaded
  (size/license reasons — see `docs/model_card.md`). The shipped/tested
  model is still the synthetic one.
- **Live NIC capture untested end-to-end.** No Npcap/root capture rights
  in the dev environment used so far. Pcap replay and everything up to
  the actual sniff (warm-up, normalization, the "unavailable" guard
  clause) are covered; a real NIC was never attached.
- **CI has never actually run.** It's correctly positioned at this repo's
  own `.github/workflows/nids-ci.yml` now that it's pushed to GitHub, but
  no push has triggered it yet — first real signal on whether it's green
  will be the next push (or trigger it manually from the Actions tab).
- **No LICENSE file** — deliberately left as your call, not added
  unilaterally.
- **Local venv/model artifacts are not in the repo** (by design —
  `.venv/`, `models/*.joblib` are gitignored) — after the restart you'll
  need to recreate the venv and retrain/re-point at a model before
  anything that needs `NIDS_ML_ENABLED=true` will work again.

## To resume after restart

```bash
cd "C:\Users\monsx\OneDrive\Documents\Abhi_Portfolio\IDS(Intrusion Detection system)"
python -m venv .venv
.venv\Scripts\activate            # PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"

nids train --dataset synthetic --out models/anomaly_model.joblib
nids replay tests/fixtures/demo_traffic.pcap   # or: make check

git remote -v                     # confirms origin points at the GitHub repo above
git log --oneline                 # confirms local history matches what's pushed
```

No servers, databases, or background processes were left running — the
throwaway Postgres instance used for testing was stopped and its data
directory deleted before this note was written.
