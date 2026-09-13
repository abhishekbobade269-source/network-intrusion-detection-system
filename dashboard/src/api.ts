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
  const query = new URLSearchParams();
  if (params.limit) query.set("limit", String(params.limit));
  if (params.severity) query.set("severity", params.severity);
  if (params.srcIp) query.set("src_ip", params.srcIp);
  return request<Alert[]>(`/alerts?${query.toString()}`);
}

export function fetchAlertStats(): Promise<AlertStats> {
  return request<AlertStats>("/stats");
}

export function fetchEngineStats(): Promise<EngineStats> {
  return request<EngineStats>("/stats/engine");
}

export function fetchCapabilities(): Promise<Capabilities> {
  return request<Capabilities>("/system/capabilities");
}

export interface StartCaptureBody {
  mode: "live" | "pcap";
  iface?: string;
  pcap_path?: string;
  bpf_filter?: string;
}

export function startCapture(body: StartCaptureBody, apiKey: string): Promise<unknown> {
  return request("/system/capture/start", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
    body: JSON.stringify(body),
  });
}

export function stopCapture(apiKey: string): Promise<unknown> {
  return request("/system/capture/stop", {
    method: "POST",
    headers: { "X-API-Key": apiKey },
  });
}

export { ApiError };
