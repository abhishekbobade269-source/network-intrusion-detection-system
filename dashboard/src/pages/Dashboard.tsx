import { motion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import "../App.css";
import { fetchAlertStats, fetchAlerts, fetchCapabilities, fetchEngineStats } from "../api";
import { AlertsTable } from "../components/AlertsTable";
import { CaptureControl } from "../components/CaptureControl";
import { ConnectionBadge } from "../components/ConnectionBadge";
import { StatsPanel } from "../components/StatsPanel";
import { DEMO_MODE } from "../demoStore";
import { useAlertsFeed } from "../hooks/useAlertsFeed";
import type { Alert, AlertStats, Capabilities, EngineStats } from "../types";

const POLL_INTERVAL_MS = 5000;

const column = {
  hidden: { opacity: 0, y: 14 },
  visible: (delay: number) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, delay, ease: [0.16, 1, 0.3, 1] as const },
  }),
};

export function Dashboard() {
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
      {DEMO_MODE && (
        <div className="demo-banner">
          <span className="demo-badge">DEMO</span>
          Synthetic, replayed traffic — not a live network feed.{" "}
          <a href="https://github.com/abhishekbobade269-source/network-intrusion-detection-system">
            Real detection engine + source on GitHub ↗
          </a>
        </div>
      )}

      <header className="app-header">
        <div className="app-header-title">
          <span className="eyebrow">Live console</span>
          <h1>NIDS</h1>
        </div>
        <div className="app-header-actions">
          <ConnectionBadge connected={connected} />
          {DEMO_MODE && (
            <Link to="/" className="exit-console">
              Exit console
            </Link>
          )}
        </div>
      </header>

      {fetchError && (
        <p className="error">
          Couldn't reach the API ({fetchError}) — is it running and is VITE_API_BASE_URL correct?
        </p>
      )}

      <main className="layout">
        <motion.div
          className="column"
          initial="hidden"
          animate="visible"
          custom={0}
          variants={column}
        >
          <StatsPanel alertStats={alertStats} engineStats={engineStats} />
          <CaptureControl capabilities={capabilities} engineStats={engineStats} onChanged={refresh} />
        </motion.div>
        <motion.div
          className="column column-wide"
          initial="hidden"
          animate="visible"
          custom={0.12}
          variants={column}
        >
          <AlertsTable alerts={alerts} live={live} />
        </motion.div>
      </main>
    </div>
  );
}
