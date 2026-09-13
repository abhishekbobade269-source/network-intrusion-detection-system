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
