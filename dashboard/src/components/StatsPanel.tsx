import { motion, useMotionValue, useTransform, animate } from "framer-motion";
import { useEffect, useRef } from "react";
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
        <Stat label="Total alerts" value={alertStats?.total} />
        <Stat label="Packets seen" value={engineStats?.packets_seen} />
        <Stat label="Active flows" value={engineStats?.active_flows} />
        <Stat
          label="Capture"
          value={engineStats?.is_capturing ? `running (${engineStats.capture_mode})` : "stopped"}
        />
        <Stat label="ML scoring" value={engineStats?.ml_enabled ? "enabled" : "disabled"} />
      </div>

      {engineStats?.last_capture_error && (
        <p className="error" title={engineStats.last_capture_error}>
          Last capture failed: {engineStats.last_capture_error}
        </p>
      )}

      {alertStats && (
        <div className="severity-bars">
          {SEVERITY_ORDER.map((sev) => {
            const count = alertStats.by_severity[sev] ?? 0;
            const max = Math.max(1, alertStats.total);
            return (
              <div key={sev} className="severity-row">
                <span className={`sev-label sev-${sev}`}>{sev}</span>
                <div className="bar-track">
                  <motion.div
                    className={`bar-fill sev-${sev}`}
                    initial={false}
                    animate={{ width: `${(count / max) * 100}%` }}
                    transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
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

function Stat({ label, value }: { label: string; value: string | number | undefined }) {
  return (
    <div className="stat">
      <div className="stat-value">
        {typeof value === "number" ? <CountUp value={value} /> : (value ?? "—")}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

/** Counts up to `value` instead of jumping — the difference between a
 * dashboard that feels alive and one that just re-renders a number. */
function CountUp({ value }: { value: number }) {
  const motionValue = useMotionValue(value);
  const rounded = useTransform(motionValue, (v) => Math.round(v).toLocaleString());
  const prev = useRef(value);

  useEffect(() => {
    const controls = animate(prev.current, value, {
      duration: 0.7,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => motionValue.set(v),
    });
    prev.current = value;
    return () => controls.stop();
  }, [value, motionValue]);

  return <motion.span>{rounded}</motion.span>;
}
