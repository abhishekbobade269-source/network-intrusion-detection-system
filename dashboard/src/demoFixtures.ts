import type { Alert, AlertStats, Capabilities, EngineStats, LiveDetection } from "./types";

/**
 * Demo-mode data: a recorded shape of the alerts this pipeline actually
 * produced replaying tests/fixtures/demo_traffic.pcap against the real
 * detection engine (see docs/architecture.md) — not invented numbers.
 * Timestamps are generated fresh on load so the feed always looks current.
 */

interface FixtureAlert {
  detector: Alert["detector"];
  rule_id: string;
  name: string;
  severity: Alert["severity"];
  confidence: number;
  description: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
}

const FIXTURES: FixtureAlert[] = [
  {
    detector: "signature",
    rule_id: "TCP_NULL_SCAN",
    name: "TCP NULL scan probe",
    severity: "medium",
    confidence: 0.75,
    description:
      "TCP flow with no flags set at all (no SYN/ACK/FIN/RST/PSH/URG) and very few packets — classic nmap -sN NULL-scan probe.",
    src_ip: "198.51.100.9",
    dst_ip: "10.0.0.5",
    src_port: 40024,
    dst_port: 24,
    protocol: 6,
  },
  {
    detector: "signature",
    rule_id: "HOST_PORT_SCAN",
    name: "Port scan detected",
    severity: "high",
    confidence: 0.95,
    description: "198.51.100.9 touched 30 distinct (host, port) pairs in the last 30s",
    src_ip: "198.51.100.9",
    dst_ip: "10.0.0.5",
    src_port: 40030,
    dst_port: 30,
    protocol: 6,
  },
  {
    detector: "signature",
    rule_id: "ICMP_FLOOD",
    name: "ICMP flood",
    severity: "high",
    confidence: 0.8,
    description:
      "Abnormally high ICMP packet rate on one flow — consistent with a ping flood / ICMP-based DoS.",
    src_ip: "203.0.113.9",
    dst_ip: "10.0.0.5",
    src_port: 0,
    dst_port: 0,
    protocol: 1,
  },
  {
    detector: "signature",
    rule_id: "TCP_SYN_FLOOD_FLOW",
    name: "TCP SYN flood indicator",
    severity: "high",
    confidence: 0.85,
    description:
      "A single flow dominated by SYNs with essentially no completed handshake and a very high packet rate — indicative of a SYN flood against this destination.",
    src_ip: "192.0.2.44",
    dst_ip: "10.0.0.5",
    src_port: 51022,
    dst_port: 443,
    protocol: 6,
  },
  {
    detector: "signature",
    rule_id: "SUSPECTED_DATA_EXFILTRATION",
    name: "Suspected data exfiltration",
    severity: "high",
    confidence: 0.6,
    description:
      "Large, heavily one-directional outbound transfer sustained over a long-lived flow — shape consistent with bulk exfiltration rather than typical request/response traffic.",
    src_ip: "10.0.0.5",
    dst_ip: "198.51.100.77",
    src_port: 54210,
    dst_port: 443,
    protocol: 6,
  },
  {
    detector: "signature",
    rule_id: "SUSPECTED_C2_BEACONING",
    name: "Suspected C2 beaconing",
    severity: "medium",
    confidence: 0.5,
    description:
      "Long-lived, low-volume flow with very regular inter-arrival timing — shape consistent with periodic command-and-control check-ins.",
    src_ip: "10.0.0.5",
    dst_ip: "203.0.113.201",
    src_port: 55001,
    dst_port: 8443,
    protocol: 6,
  },
  {
    detector: "anomaly",
    rule_id: "ML_ANOMALY",
    name: "Anomalous flow (ML)",
    severity: "critical",
    confidence: 1.0,
    description:
      "Isolation-forest anomaly score 1.000 for flow 198.51.100.9:40024 -> 10.0.0.5:24",
    src_ip: "198.51.100.9",
    dst_ip: "10.0.0.5",
    src_port: 40024,
    dst_port: 24,
    protocol: 6,
  },
  {
    detector: "anomaly",
    rule_id: "ML_ANOMALY",
    name: "Anomalous flow (ML)",
    severity: "critical",
    confidence: 0.93,
    description:
      "Isolation-forest anomaly score 0.930 for flow 203.0.113.9:0 -> 10.0.0.5:0",
    src_ip: "203.0.113.9",
    dst_ip: "10.0.0.5",
    src_port: 0,
    dst_port: 0,
    protocol: 1,
  },
];

function uuid(seed: number): string {
  const hex = seed.toString(16).padStart(8, "0");
  return `${hex}-demo-4a1f-9c3e-${seed.toString(16).padStart(12, "0")}`;
}

/** Builds a stable, already-populated alert history — the dashboard's
 * "on load" state, so the first frame shows a working feed, not an empty
 * shell waiting for a live connection that will never come.
 */
export function buildInitialAlerts(count = 42): Alert[] {
  const now = Date.now();
  const alerts: Alert[] = [];
  for (let i = 0; i < count; i++) {
    const f = FIXTURES[i % FIXTURES.length];
    const at = new Date(now - i * 41_000 - (i % 5) * 3_000);
    alerts.push({
      id: uuid(i + 1),
      created_at: at.toISOString(),
      detector: f.detector,
      rule_id: f.rule_id,
      name: f.name,
      severity: f.severity,
      confidence: f.confidence,
      description: f.description,
      src_ip: f.src_ip,
      dst_ip: f.dst_ip,
      src_port: f.src_port,
      dst_port: f.dst_port,
      protocol: f.protocol,
      evidence: { src_ip: f.src_ip, dst_port: f.dst_port },
      acknowledged: i % 7 === 0,
    });
  }
  return alerts;
}

export function computeStats(alerts: Alert[]): AlertStats {
  const by_severity: Record<string, number> = {};
  const by_detector: Record<string, number> = {};
  const bySrc = new Map<string, number>();
  for (const a of alerts) {
    by_severity[a.severity] = (by_severity[a.severity] ?? 0) + 1;
    by_detector[a.detector] = (by_detector[a.detector] ?? 0) + 1;
    bySrc.set(a.src_ip, (bySrc.get(a.src_ip) ?? 0) + 1);
  }
  const top_src_ips = [...bySrc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10) as [
    string,
    number,
  ][];
  return { total: alerts.length, by_severity, by_detector, top_src_ips };
}

export function buildEngineStats(alerts: Alert[], capturing: boolean): EngineStats {
  return {
    packets_seen: 1500 + alerts.length * 3,
    flows_evaluated: 44 + alerts.length,
    active_flows: capturing ? 3 + (alerts.length % 5) : 0,
    ml_enabled: true,
    is_capturing: capturing,
    capture_mode: capturing ? "pcap" : null,
    capture_source: capturing ? "tests/fixtures/demo_traffic.pcap" : null,
    last_capture_error: null,
  };
}

export const DEMO_CAPABILITIES: Capabilities = {
  can_capture_live: true,
  ml_model_loaded: true,
  rules_loaded: 9,
};

let liveSeed = 1000;

/** Synthesizes one more "live" detection — same shape a real websocket
 * push carries — cycling through the recorded fixture set.
 */
export function nextLiveDetection(): LiveDetection {
  const f = FIXTURES[liveSeed % FIXTURES.length];
  liveSeed += 1;
  return {
    type: "detection",
    at: new Date().toISOString(),
    rule_id: f.rule_id,
    name: f.name,
    detector: f.detector,
    severity: f.severity,
    confidence: f.confidence,
    description: f.description,
    src_ip: f.src_ip,
    dst_ip: f.dst_ip,
    dst_port: f.dst_port,
  };
}
