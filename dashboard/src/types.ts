export type Severity = "low" | "medium" | "high" | "critical";
export type DetectorKind = "signature" | "anomaly";

export interface Alert {
  id: string;
  created_at: string;
  detector: DetectorKind;
  rule_id: string;
  name: string;
  severity: Severity;
  confidence: number;
  description: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  evidence: Record<string, unknown>;
  acknowledged: boolean;
}

/** Shape pushed over /ws/alerts — a subset of `Alert`, not yet persisted-and-reread. */
export interface LiveDetection {
  type: "detection";
  at: string;
  rule_id: string;
  name: string;
  detector: DetectorKind;
  severity: Severity;
  confidence: number;
  description: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
}

export interface AlertStats {
  total: number;
  by_severity: Record<string, number>;
  by_detector: Record<string, number>;
  top_src_ips: [string, number][];
}

export interface EngineStats {
  packets_seen: number;
  flows_evaluated: number;
  active_flows: number;
  ml_enabled: boolean;
  is_capturing: boolean;
  capture_mode: string | null;
  capture_source: string | null;
}

export interface Capabilities {
  can_capture_live: boolean;
  ml_model_loaded: boolean;
  rules_loaded: number;
}
