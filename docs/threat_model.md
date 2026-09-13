# Threat model & scope

## What this system is

A single-sensor, flow-based hybrid NIDS: it watches traffic on one
interface (or replays a capture), reconstructs flows, and flags flows that
match a known-bad signature or look statistically anomalous. It is a
**detector**, not a **preventer** — everything downstream of a `Finding`
(store, notify, display) is passive; nothing here drops packets, resets
connections, or blocks an IP.

## What it can catch (and has an automated test or a manual `nids replay`
demonstration for)

| Pattern | Detector | Rule/component |
|---|---|---|
| TCP NULL / FIN / XMAS / half-open scan probe | signature | `src/nids/rules/definitions/scans.yaml` |
| Port sweep / host sweep from one source | signature (stateful) | `nids.rules.scan_detector.PortScanDetector` |
| SYN / ICMP / UDP flood | signature | `src/nids/rules/definitions/floods.yaml` |
| Large one-directional transfer (exfil-shaped) | signature | `SUSPECTED_DATA_EXFILTRATION` |
| Regular, low-volume, long-lived flow (beacon-shaped) | signature | `SUSPECTED_C2_BEACONING` |
| Anything that doesn't look like the trained benign baseline | ML (Isolation Forest) | `nids.ml` |

## Explicit non-goals

- **Encrypted payload inspection.** Detection is entirely flow/metadata
  based (sizes, timing, flags, ports) — it never inspects TLS/application
  payload content, so it cannot detect e.g. malware signatures inside an
  HTTPS body. This is a deliberate scope boundary, not an oversight: payload
  inspection either requires TLS termination (a very different trust/deploy
  model) or is limited to plaintext protocols.
- **Multi-sensor / distributed correlation.** One process, one capture
  source, one Postgres instance. Correlating alerts across multiple
  vantage points (a real SOC's SIEM layer) is out of scope here.
- **Active response.** No firewall/iptables/null-route integration. The
  `alert_webhook_url` notification path is the intended hook for *you* to
  wire into a response system if you want one — this project deliberately
  stops at "tell a human or a downstream system," not "act unilaterally."
- **Perimeter/inline deployment.** This is built and tested as a passive
  tap/mirror-port consumer (or offline pcap analysis) — it is not hardened
  as an inline traffic path, and putting a Python asyncio process inline on
  a production link is its own separate engineering problem this project
  doesn't attempt.
- **Adversarial-ML robustness.** The anomaly model is not hardened against
  an attacker who knows its feature set and deliberately shapes traffic to
  blend into the benign distribution (a known, general weakness of
  anomaly-based IDS, not specific to this implementation).
- **IPv6-complete flow features.** `Packet`/`FlowRecord` support IPv6
  addresses end-to-end, but the shipped signature rules were written and
  validated against IPv4 attack shapes; IPv6-specific attack patterns
  (extension-header abuse, ND spoofing) have no dedicated rules yet.

## Trust boundaries

- **The capture source is untrusted input.** Every field derived from a
  packet (`nids.capture.packet.Packet`) is attacker-controlled — the
  parser (`nids.capture._scapy_parse.from_scapy`) is defensive: a packet
  missing an IP layer returns `None` and is skipped rather than raising, so
  a single malformed/adversarial packet can't take capture down.
- **The API's write path is the other boundary.** `/system/capture/*` and
  `/alerts/{id}/acknowledge` are gated behind a static API key
  (`NIDS_API_KEY`) via `nids.api.deps.require_api_key` — unset in local
  dev (no-op), **must** be set in any shared/production deployment. Read
  endpoints (`GET /alerts`, `/stats`, `/ws/alerts`) are unauthenticated by
  design (a read-only dashboard); put this behind your own auth/reverse
  proxy if the deployment is anything but a private network.
- **The webhook notifier is best-effort and isolated.** A failing/slow
  webhook endpoint logs and moves on (`nids.alerts.notifier.AlertNotifier`)
  — it can never block or crash the detection loop.
