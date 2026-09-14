import { buildInitialAlerts, detectionForRuleId, nextLiveDetection } from "./demoFixtures";
import type { Alert, LiveDetection } from "./types";

/**
 * Demo mode's entire "backend": an in-memory store the mock api.ts /
 * useAlertsFeed.ts read from, seeded with a realistic alert history and
 * grown by a simulated live feed — so the polled REST calls and the
 * "live" websocket-shaped feed stay consistent with each other, the same
 * way the real API and its DB eventually agree.
 */

export const DEMO_MODE: boolean = import.meta.env.VITE_DEMO_MODE === "true";

let alerts: Alert[] = buildInitialAlerts();
let capturing = true;

export function getAlerts(): Alert[] {
  return alerts;
}

export function isCapturing(): boolean {
  return capturing;
}

export function setCapturing(value: boolean): void {
  capturing = value;
}

function uuidFromDetection(d: LiveDetection): string {
  return `live-${d.at}-${d.rule_id}-${Math.random().toString(16).slice(2, 10)}`;
}

function recordDetection(detection: LiveDetection): LiveDetection {
  const alert: Alert = {
    id: uuidFromDetection(detection),
    created_at: detection.at,
    detector: detection.detector,
    rule_id: detection.rule_id,
    name: detection.name,
    severity: detection.severity,
    confidence: detection.confidence,
    description: detection.description,
    src_ip: detection.src_ip,
    dst_ip: detection.dst_ip,
    src_port: 0,
    dst_port: detection.dst_port,
    protocol: detection.rule_id === "ICMP_FLOOD" ? 1 : 6,
    evidence: { src_ip: detection.src_ip, dst_port: detection.dst_port },
    acknowledged: false,
  };
  alerts = [alert, ...alerts].slice(0, 300);
  return detection;
}

/** Advances the simulated feed by one detection, recording it into the
 * alert history too, and returns it for the live feed to broadcast.
 */
export function tickDemoFeed(): LiveDetection {
  return recordDetection(nextLiveDetection());
}

/** Fires one specific detector on demand — the Landing page's scenario
 * picker uses this so a visitor can trigger e.g. a port scan by name.
 * The alert lands in this same store, so it's already sitting in the
 * console's history if they go on to /dashboard. */
export function injectScenario(ruleId: string): LiveDetection | null {
  const base = detectionForRuleId(ruleId);
  if (!base) return null;
  return recordDetection({ ...base, at: new Date().toISOString() });
}

export function acknowledgeDemoAlert(id: string): Alert | null {
  const row = alerts.find((a) => a.id === id);
  if (!row) return null;
  row.acknowledged = true;
  alerts = [...alerts];
  return row;
}
