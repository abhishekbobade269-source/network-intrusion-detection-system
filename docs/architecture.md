# Architecture

## Data flow

```
Packet source (live NIC | pcap file)
        │
        ▼  scapy → nids.capture.packet.Packet (normalized, source-agnostic)
Packet normalization
        │
        ▼  nids.flows.FlowTracker: 5-tuple keyed, bidirectional aggregation
FlowRecord (finalized on FIN/RST, or on idle/active timeout via .poll())
        │
        ├──▶ nids.rules.RuleEngine        (YAML per-flow threshold rules)
        ├──▶ nids.rules.PortScanDetector  (stateful, cross-flow: distinct
        │                                  (host, port) pairs per source
        │                                  IP in a sliding window)
        └──▶ nids.ml.AnomalyScorer        (Isolation Forest over the same
                                            feature vector, trained on
                                            benign-only traffic)
        │
        ▼  zero or more Finding
nids.detection.DetectionEngine._evaluate()
        │
        ▼  nids.detection.runner.DetectionRunner (async orchestration)
   ┌────┴─────────────────┬───────────────────────┐
   ▼                      ▼                       ▼
AlertStore           AlertNotifier          WebSocketManager
(Postgres, via        (webhook, above       (broadcasts to
AlertCreate)           a severity floor)     the dashboard)
```

## Why a flow, not a packet, is the unit of detection

A single packet rarely tells you anything — "a SYN arrived" is meaningless
without knowing what came before and after it on that connection. Almost
every useful signal here (scan shape, flood rate, exfil volume, beaconing
regularity) is a property of a *conversation over time*, which is exactly
what `FlowRecord` captures: byte/packet counts in each direction, packet
length distribution (mean/std/min/max via Welford's online algorithm, so no
per-packet buffering), inter-arrival timing, and TCP flag counts. This is
also why the ML model and the rule engine share one feature schema
(`nids.ml.features.FEATURE_COLUMNS` mirrors `FlowRecord.to_feature_dict()`)
— they're two different ways of asking the same question about the same
object.

## Why two detectors instead of one

- **Signatures are precise and explainable.** "This flow had 30 SYNs and 0
  ACKs" is either true or false — no training data, no probability, and a
  human can read the YAML rule and know exactly why it fired. Their
  weakness: they only catch shapes someone thought to write a rule for.
- **The anomaly model generalizes.** An Isolation Forest trained only on
  benign traffic doesn't need to have seen a particular attack before to
  flag a flow that just doesn't look like anything normal. Its weakness:
  it's a statistical opinion, not a certificate — it will have false
  positives, and its accuracy is only as good as how representative its
  training data is of your real traffic (see `docs/model_card.md`).

Both run on every flow; both emit the same `Finding` type
(`nids.common.Finding`) so nothing downstream needs to know which one
fired.

## Live capture privileges

Live capture (`scapy.sendrecv.AsyncSniffer`) needs to open a raw socket:

- **Linux**: run as root, or grant the interpreter the capability once —
  `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))`
  — instead of running the whole process as root.
- **macOS**: run as root (`sudo`), or grant your terminal/Python "Full Disk
  Access" is *not* what's needed here — it's raw-socket access, which macOS
  gates behind root.
- **Windows**: install [Npcap](https://npcap.com/) (WinPcap's maintained
  successor) and run as Administrator.
- **Docker**: the container needs `--cap-add=NET_RAW --cap-add=NET_ADMIN`
  (see `docker-compose.yml`) and, to see the *host's* real interfaces
  rather than the container's own virtual one, `network_mode: host`.

None of this is needed for pcap replay or dataset-based training — only
for `nids sniff` / `POST /system/capture/start {"mode": "live"}`.

## The first-packet-loss bug (and why `warm_up_scapy_layers()` exists)

Scapy dissects a captured/read packet into its sub-layers **once**,
eagerly, using whatever `bind_layers()` registrations exist *at that
instant* — `scapy.layers.inet` registers `Ether -> IP` (ethertype 0x0800)
and `IP -> {TCP, UDP, ICMP}` as an *import-time* side effect. Doing that
import lazily inside the per-packet parser (as this codebase originally
did, inside `nids.capture._scapy_parse.from_scapy`) meant the very first
packet of every capture session was dissected *before* those bindings
existed — silently downgraded to an opaque `Raw` payload forever, no
matter what got imported a microsecond later for packet #2 onward.

Both capture entry points (`LiveSniffer.packets()`, `iter_pcap()`) now call
`nids.capture._scapy_parse.warm_up_scapy_layers()` before touching the
reader/sniffer at all. If you add a new capture source, call it there too
— `tests/integration/test_pcap_replay.py`'s packet-count assertion
(`engine.packets_seen == 90`, matching every packet in the fixture) is the
regression guard for this specific class of bug.

## Flow expiry and the `poll()` tick

Not every flow gets a clean TCP close (UDP has none at all; scans and
floods often don't either), so `FlowTracker` needs a heartbeat, not just
"react to packets" — that's `DetectionEngine.poll(now)` /
`FlowTracker.poll(now)`, called once per `poll_interval_s` (default 5s) by
`DetectionRunner`. Live capture polls against wall-clock time; pcap replay
polls against the *replayed* packet timestamps instead (see
`DetectionRunner.run_pcap`'s `_pcap_clock`), so idle/active timeouts behave
identically whether a capture replays in 2 seconds or 20 minutes.

## Bugs this project's own tests caught (and what fixed them)

Worth keeping visible rather than quietly fixed-and-forgotten — each of
these was invisible until a *real* dependency (a real Postgres, a real
ASGI websocket handshake, a CICIDS2017-shaped CSV) was actually exercised:

- **The first-packet-loss bug** — see above.
- **`/ws/alerts` crashed on every single connection attempt.** Its
  `Depends(get_app_state)` sub-dependency was typed for an HTTP `Request`,
  which FastAPI cannot supply to a websocket route (there is no `Request`
  in a websocket scope) — it failed with a bare `TypeError: get_app_state()
  missing 1 required positional argument`. Invisible to every test that
  only exercised `WebSocketManager` directly; caught the moment a test
  drove a real ASGI websocket handshake through the route
  (`tests/integration/test_websocket.py`). Fixed by adding a
  websocket-specific dependency, `nids.api.deps.get_app_state_ws`.
- **`load_cicids2017` raised `KeyError` on any real input.** It mapped
  CICFlowMeter's columns onto `FEATURE_COLUMNS` but never computed
  `total_packets`/`total_bytes` — CICFlowMeter only has the forward/
  backward halves, not the combined totals `FEATURE_COLUMNS` requires — so
  `_clean()`'s `dropna` crashed looking for columns that were never
  created. Zero test coverage had ever run this function against
  real-shaped data (the real dataset is multi-GB and not bundled); caught
  by a hand-built CSV shaped like real CICFlowMeter output
  (`tests/unit/test_ml_datasets.py`). Fixed by deriving the two totals
  from the forward/backward columns right after the rename.
- **The test suite itself was flaky by construction, not by chance.**
  `nids.db.session.init_engine()`/`get_sessionmaker()` are `@lru_cache`'d
  — correct for a long-running server process (one engine for its whole
  lifetime) — but pytest-asyncio's default per-function event loop tore
  that loop down after each test, so whichever DB-touching test ran next
  tried to clean up or reuse a pooled asyncpg connection against an
  already-closed loop (`RuntimeError: Event loop is closed`). Not a
  production bug — the app only ever runs one event loop for its whole
  life — but a real trap for testing an app built this way. Fixed in
  `pyproject.toml`, not application code:
  `asyncio_default_fixture_loop_scope = "session"` and
  `asyncio_default_test_loop_scope = "session"`, so the whole test session
  shares one loop, matching the cached engine's actual lifetime assumption.
- **The containerized deployment loaded zero signature rules — and the
  API couldn't reach Postgres either, silently.** Both only surfaced when
  `docker compose up` was actually run for the first time, not from
  reading the Dockerfile/compose file:
  - `Settings.rules_dir`'s default was computed by walking up a fixed
    number of parent directories from `config.py`'s own file location,
    assuming a source-tree layout (`<repo root>/src/nids/config.py`).
    That's true for an editable install but false for a real wheel
    install (`site-packages/nids/config.py`) — exactly how the Dockerfile
    installs the app — so `rules_dir` pointed at a path that never
    existed, and the rule engine silently started with 0 rules loaded, no
    error. Fixed by anchoring to `config.py`'s own package directory
    (`Path(__file__).resolve().parent`) instead of a "project root"
    guess — correct under any install mode, editable or wheel. Guarded by
    `tests/unit/test_config.py`.
  - The compose file's `api` service used `network_mode: host` so live
    capture could see the host's real interfaces. On Docker Desktop
    (Windows/Mac, where the engine runs inside a VM) that's a different
    network namespace than "the actual host" — it broke two things at
    once: the API stopped being reachable at `localhost:8000` from the
    host at all, and, inside the container, the `postgres` hostname
    became unresolvable (host-mode containers aren't attached to
    compose's bridge network, which is what provides that DNS). The
    second failure was invisible at startup specifically because
    `NIDS_ENVIRONMENT=production` skips the dev-mode DB-connectivity probe
    that would otherwise have logged a warning — so the app reported
    "started successfully" while every future DB-backed request would
    have failed. Fixed by switching `api` to the default bridge network
    with an explicit `ports: ["8000:8000"]` — `network_mode: host` only
    ever bought anything on native Linux Docker hosts in the first place,
    and even there only for live capture, which the documented default
    demo path (pcap replay) doesn't need at all.

  Verified past "it builds" all the way through: `docker compose up
  --build`, migrations ran, `POST /system/capture/start` replayed the
  demo pcap through the running container, alerts showed up over
  `GET /alerts` and in the dashboard's live feed in a real browser — with
  console clean of errors.

- **Live capture in the container needed two more fixes before it
  actually worked**, found by deliberately trying it (a real port scan
  from a second container) rather than trusting `cap_add`:
  - `docker-compose.yml`'s `cap_add: [NET_RAW, NET_ADMIN]` alone did
    nothing for a non-root process — Linux capabilities added to a
    *container's* bounding set aren't automatically usable by a
    non-root user inside it (`USER nids` in the Dockerfile) without file
    capabilities on the actual binary. `sniff()` raised a bare
    `PermissionError: Operation not permitted` until the Dockerfile
    started actually running `setcap cap_net_raw,cap_net_admin=eip` on
    the interpreter — `libcap2-bin` had been installed for exactly this
    with a comment saying so, but the `setcap` invocation itself was
    never added.
  - Past that, `sniff(filter="ip or ip6")` raised
    `Scapy_Exception: Cannot set filter: libpcap is not available` — the
    slim Debian base image has no `libpcap`/`tcpdump`, which is what
    scapy shells out to on Linux to compile a BPF filter string at all.
    Fixed by installing `tcpdump` (pulls in `libpcap` as a dependency).

  With both fixed: `POST /system/capture/start {"mode":"live","iface":"eth0"}`
  against the running container, then a real `nc`-based port scan from a
  second container on the same Docker network, produced genuine live
  packets (`packets_seen` climbing in real time) and a real
  `HOST_PORT_SCAN` alert — not a replay, an actual live capture, for the
  first time since this project started (every prior session had no
  Npcap/root capture rights available at all to test this with).

- **A production deployment with no `NIDS_API_KEY` set — exactly what
  `docker-compose.yml` produces by default — left every control endpoint
  completely open.** Confirmed exploitable directly: `POST
  /system/capture/stop` against the real running container succeeded
  with zero credentials. Fixed fail-safe rather than fail-open:
  `nids.api.main.lifespan` now generates a random key and logs it once
  when `is_production` and no key is configured, instead of silently
  requiring nothing. See `docs/threat_model.md`.

- **`database_url` was logged with its password in plain text** on the
  dev-mode DB-unreachable warning path — a real credential-leak risk
  (that log line ends up in whatever aggregator/monitoring tool you ship
  logs to). Fixed with `Settings.database_url_masked`, which redacts the
  password before anything logs the DSN.

- **`POST /system/capture/start` returned `200 "started"` for a pcap path
  that could never work**, with the actual `FileNotFoundError` surfacing
  only as a raw, unstructured Python traceback in server logs minutes
  later, with zero feedback to the caller. Fixed two ways: the common
  case (a missing/wrong `pcap_path`) is now validated synchronously and
  rejected with an immediate `400`; anything that fails later, inside the
  capture thread, is caught, logged cleanly through structlog instead of
  crashing the thread silently, and recorded on
  `DetectionRunner.last_error`, surfaced through `GET /stats/engine`'s
  `last_capture_error` field and shown directly in the dashboard.

- **The dashboard's own Docker container reported `unhealthy` forever**,
  despite serving every request correctly — `docker compose ps` is
  exactly the kind of thing a technical reviewer glances at. Root cause:
  its `HEALTHCHECK` ran `wget http://localhost/`, which resolved to
  `::1` first inside the container; nginx only listens on `0.0.0.0:80`
  (IPv4), and busybox `wget` doesn't fall back to IPv4 after an IPv6
  connection refusal. Fixed by hardcoding `127.0.0.1` in the healthcheck
  instead of `localhost`.

## Extending detection

- **New signature**: add a rule to a YAML file under
  `src/nids/rules/definitions/` — no code change, no restart-breaking
  schema migration. See the existing files for the condition grammar
  (`field`/`op`/`value` triples, ANDed together).
- **New cross-flow / stateful signature**: follow the shape of
  `nids.rules.scan_detector.PortScanDetector` — anything that needs memory
  across flows (not just thresholds on one flow) belongs here, not in YAML.
- **Retrain the ML model** on your own labeled traffic or CICIDS2017: see
  `nids.ml.train` and `docs/model_card.md`.
