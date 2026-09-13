import { useCallback, useEffect, useState } from "react";
import "./App.css";
import { fetchAlertStats, fetchAlerts, fetchCapabilities, fetchEngineStats } from "./api";
import { AlertsTable } from "./components/AlertsTable";
import { CaptureControl } from "./components/CaptureControl";
import { ConnectionBadge } from "./components/ConnectionBadge";
import { StatsPanel } from "./components/StatsPanel";
import { useAlertsFeed } from "./hooks/useAlertsFeed";
import type { Alert, AlertStats, Capabilities, EngineStats } from "./types";

const POLL_INTERVAL_MS = 5000;

function App() {
  const { connected, live } = useAlertsFeed();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [alertStats, setAlertStats] = useState<AlertStats | null>(null);
  const [engineStats, setEngineStats] = useState<EngineStats | null>(null);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    Promise.all([fetchAlerts({ limit: 100 }), fetchAlertStats(), fetchEngineStats()])
      .then(([a, s, e]) => {
        setAlerts(a);
        setAlertStats(s);
        setEngineStats(e);
        setFetchError(null);
      })
      .catch((err: unknown) => setFetchError(String(err)));
  }, []);

  useEffect(() => {
    fetchCapabilities().then(setCapabilities).catch(() => undefined);
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <div className="app">
      <header className="app-header">
        <h1>NIDS — live alerts</h1>
        <ConnectionBadge connected={connected} />
      </header>

      {fetchError && (
        <p className="error">
          Couldn't reach the API ({fetchError}) — is it running and is VITE_API_BASE_URL correct?
        </p>
      )}

      <main className="layout">
        <div className="column">
          <StatsPanel alertStats={alertStats} engineStats={engineStats} />
          <CaptureControl capabilities={capabilities} engineStats={engineStats} onChanged={refresh} />
        </div>
        <div className="column column-wide">
          <AlertsTable alerts={alerts} live={live} />
        </div>
      </main>
    </div>
  );
}

export default App;
