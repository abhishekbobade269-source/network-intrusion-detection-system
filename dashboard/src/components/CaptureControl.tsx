import { useState } from "react";
import { ApiError, getStoredApiKey, setStoredApiKey, startCapture, stopCapture } from "../api";
import type { Capabilities, EngineStats } from "../types";

interface Props {
  capabilities: Capabilities | null;
  engineStats: EngineStats | null;
  onChanged: () => void;
}

export function CaptureControl({ capabilities, engineStats, onChanged }: Props) {
  const [mode, setMode] = useState<"live" | "pcap">("pcap");
  const [iface, setIface] = useState("");
  const [pcapPath, setPcapPath] = useState("");
  const [apiKey, setApiKey] = useState(getStoredApiKey());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isCapturing = engineStats?.is_capturing ?? false;

  const persistApiKey = (value: string) => {
    setApiKey(value);
    setStoredApiKey(value);
  };

  const handleStart = async () => {
    setBusy(true);
    setError(null);
    try {
      await startCapture(
        {
          mode,
          iface: mode === "live" ? iface || undefined : undefined,
          pcap_path: mode === "pcap" ? pcapPath || undefined : undefined,
        },
        apiKey,
      );
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? `${err.status}: ${err.message}` : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleStop = async () => {
    setBusy(true);
    setError(null);
    try {
      await stopCapture(apiKey);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? `${err.status}: ${err.message}` : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <h2>Capture control</h2>

      <label className="field">
        API key
        <input
          type="password"
          value={apiKey}
          onChange={(e) => persistApiKey(e.target.value)}
          placeholder="NIDS_API_KEY (leave blank if unset)"
        />
      </label>

      <div className="mode-toggle">
        <label>
          <input
            type="radio"
            checked={mode === "pcap"}
            onChange={() => setMode("pcap")}
            disabled={isCapturing}
          />
          Replay a pcap
        </label>
        <label>
          <input
            type="radio"
            checked={mode === "live"}
            onChange={() => setMode("live")}
            disabled={isCapturing || !capabilities?.can_capture_live}
          />
          Live capture
          {!capabilities?.can_capture_live && " (unavailable in this environment)"}
        </label>
      </div>

      {mode === "pcap" ? (
        <label className="field">
          Server-side pcap path
          <input
            value={pcapPath}
            onChange={(e) => setPcapPath(e.target.value)}
            placeholder="tests/fixtures/demo_traffic.pcap"
            disabled={isCapturing}
          />
        </label>
      ) : (
        <label className="field">
          Interface
          <input
            value={iface}
            onChange={(e) => setIface(e.target.value)}
            placeholder="eth0 / Wi-Fi"
            disabled={isCapturing}
          />
        </label>
      )}

      <div className="actions">
        <button onClick={handleStart} disabled={busy || isCapturing}>
          Start
        </button>
        <button onClick={handleStop} disabled={busy || !isCapturing} className="secondary">
          Stop
        </button>
      </div>

      {error && <p className="error">{error}</p>}
    </section>
  );
}
