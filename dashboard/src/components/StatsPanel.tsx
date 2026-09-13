import type { AlertStats, EngineStats } from "../types";

interface Props {
  alertStats: AlertStats | null;
  engineStats: EngineStats | null;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

export function StatsPanel({ alertStats, engineStats }: Props) {
  return (
    <section className="panel">
      <h2>Overview</h2>
      <div className="stat-grid">
        <Stat label="Total alerts" value={alertStats?.total ?? "—"} />
        <Stat label="Packets seen" value={engineStats?.packets_seen ?? "—"} />
        <Stat label="Active flows" value={engineStats?.active_flows ?? "—"} />
        <Stat
          label="Capture"
          value={engineStats?.is_capturing ? `running (${engineStats.capture_mode})` : "stopped"}
        />
        <Stat label="ML scoring" value={engineStats?.ml_enabled ? "enabled" : "disabled"} />
      </div>

      {alertStats && (
        <div className="severity-bars">
          {SEVERITY_ORDER.map((sev) => {
            const count = alertStats.by_severity[sev] ?? 0;
            const max = Math.max(1, alertStats.total);
            return (
              <div key={sev} className="severity-row">
                <span className={`sev-label sev-${sev}`}>{sev}</span>
                <div className="bar-track">
                  <div
                    className={`bar-fill sev-${sev}`}
                    style={{ width: `${(count / max) * 100}%` }}
                  />
                </div>
                <span className="sev-count">{count}</span>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
