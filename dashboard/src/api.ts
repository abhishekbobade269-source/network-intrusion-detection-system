import { buildEngineStats, computeStats, DEMO_CAPABILITIES } from "./demoFixtures";
import { DEMO_MODE, getAlerts, isCapturing, setCapturing } from "./demoStore";
import type { Alert, AlertStats, Capabilities, EngineStats } from "./types";

export const API_BASE_URL: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000";

export const WS_URL: string = `${API_BASE_URL.replace(/^http/, "ws")}/ws/alerts`;

const API_KEY_STORAGE_KEY = "nids.apiKey";

export function getStoredApiKey(): string {
  try {
    return localStorage.getItem(API_KEY_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setStoredApiKey(key: string): void {
  try {
    localStorage.setItem(API_KEY_STORAGE_KEY, key);
  } catch {
    // Private-browsing / disabled storage — the key just won't persist across reloads.
  }
}

class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, init);
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new ApiError(response.status, body || response.statusText);
  }
  return (await response.json()) as T;
}

export function fetchAlerts(params: {
  limit?: number;
  severity?: string;
  srcIp?: string;
}): Promise<Alert[]> {
  if (DEMO_MODE) {
    let rows = getAlerts();
    if (params.severity) rows = rows.filter((a) => a.severity === params.severity);
    if (params.srcIp) rows = rows.filter((a) => a.src_ip === params.srcIp);
    return Promise.resolve(rows.slice(0, params.limit ?? 100));
  }
  const query = new URLSearchParams();
  if (params.limit) query.set("limit", String(params.limit));
  if (params.severity) query.set("severity", params.severity);
  if (params.srcIp) query.set("src_ip", params.srcIp);
  return request<Alert[]>(`/alerts?${query.toString()}`);
}

export function fetchAlertStats(): Promise<AlertStats> {
  if (DEMO_MODE) return Promise.resolve(computeStats(getAlerts()));
  return request<AlertStats>("/stats");
}

export function fetchEngineStats(): Promise<EngineStats> {
  if (DEMO_MODE) return Promise.resolve(buildEngineStats(getAlerts(), isCapturing()));
  return request<EngineStats>("/stats/engine");
}

export function fetchCapabilities(): Promise<Capabilities> {
  if (DEMO_MODE) return Promise.resolve(DEMO_CAPABILITIES);
  return request<Capabilities>("/system/capabilities");
}

export interface StartCaptureBody {
  mode: "live" | "pcap";
  iface?: string;
  pcap_path?: string;
  bpf_filter?: string;
}

export function startCapture(body: StartCaptureBody, apiKey: string): Promise<unknown> {
  if (DEMO_MODE) {
    setCapturing(true);
    return Promise.resolve({ status: "started" });
  }
  return request("/system/capture/start", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
    body: JSON.stringify(body),
  });
}

export function stopCapture(apiKey: string): Promise<unknown> {
  if (DEMO_MODE) {
    setCapturing(false);
    return Promise.resolve({ status: "stopped" });
  }
  return request("/system/capture/stop", {
    method: "POST",
    headers: { "X-API-Key": apiKey },
  });
}

export { ApiError };
