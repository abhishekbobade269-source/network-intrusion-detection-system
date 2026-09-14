import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ThemeSwitcher } from "../components/ThemeSwitcher";
import { SignalScope } from "../components/SignalScope";
import {
  ArrowRightIcon,
  GithubMarkIcon,
  LockIcon,
  PulseIcon,
  RadarIcon,
  ScopeIcon,
  ShieldIcon,
  StackIcon,
  TowerIcon,
} from "../components/icons";
import { SCENARIOS } from "../demoFixtures";
import { injectScenario } from "../demoStore";
import type { LiveDetection } from "../types";
import "./Landing.css";

const REPO_URL = "https://github.com/abhishekbobade269-source/network-intrusion-detection-system";
const PORTFOLIO_URL = "https://abhishek-portfolio-rose.vercel.app/work/nids";

const container = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.1, delayChildren: 0.1 } },
};

const item = {
  hidden: { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
  },
};

const PIPELINE = [
  {
    n: "01",
    icon: TowerIcon,
    title: "Capture",
    body: "Live packet capture off a real NIC, or offline replay of a pcap / CICIDS2017 dataset — the same code path either way.",
  },
  {
    n: "02",
    icon: ScopeIcon,
    title: "Extract",
    body: "FlowTracker aggregates packets into per-flow features: counts, byte volume, inter-arrival timing, TCP flag ratios.",
  },
  {
    n: "03",
    icon: ShieldIcon,
    title: "Detect",
    body: "The DetectionEngine runs YAML signature rules and a stateful port-scan detector alongside an Isolation-Forest anomaly score.",
  },
  {
    n: "04",
    icon: PulseIcon,
    title: "Alert",
    body: "Findings hit AlertStore (Postgres) and /ws/alerts in the same instant — this dashboard streams them live.",
  },
];

const FEATURES = [
  {
    icon: ShieldIcon,
    title: "Signature rules",
    body: "Deterministic YAML rules catch known patterns — NULL/XMAS scans, SYN floods, ICMP floods — plus a stateful detector watching (host, port) pairs over a rolling window.",
  },
  {
    icon: RadarIcon,
    title: "ML anomaly detection",
    body: "An Isolation Forest trained only on benign traffic flags flow shapes no rule was written for — exfiltration, beaconing, anything that just looks wrong.",
  },
  {
    icon: TowerIcon,
    title: "Live or replay capture",
    body: "Point it at a live interface or replay a recorded capture. The detection engine underneath doesn't know the difference.",
  },
  {
    icon: LockIcon,
    title: "Fail-safe, not fail-open",
    body: "No NIDS_API_KEY set? The API generates and logs one at startup instead of leaving every control endpoint open — every route sits behind a rate limiter too.",
  },
  {
    icon: PulseIcon,
    title: "Live, not eventually",
    body: "Every finding is persisted to PostgreSQL and pushed over a websocket feed in the same instant — the dashboard and the database never disagree.",
  },
  {
    icon: StackIcon,
    title: "One command to run it",
    body: "docker compose up --build — FastAPI, PostgreSQL, and this dashboard, healthchecked and wired together end to end.",
  },
];

const TECH_STACK = [
  "Python",
  "FastAPI",
  "PostgreSQL",
  "scapy",
  "scikit-learn",
  "React 19",
  "Vite",
  "Framer Motion",
  "Docker Compose",
];

/** Faux telemetry for the hero panel — ticks so the panel reads as
 * "instrument," but never claims to be real traffic; the caption under
 * it says so outright. */
function useSimulatedReadout(base: number, jitter: number) {
  const [value, setValue] = useState(base);
  useEffect(() => {
    const id = setInterval(() => {
      setValue(Math.round(base + (Math.random() - 0.5) * jitter));
    }, 1400);
    return () => clearInterval(id);
  }, [base, jitter]);
  return value;
}

function PipelineTrack() {
  const reduceMotion = useReducedMotion();
  return (
    <div className="pipeline-track">
      {!reduceMotion && (
        <motion.div
          className="pipeline-track-dot"
          initial={{ left: "0%" }}
          animate={{ left: "100%" }}
          transition={{ duration: 3.2, repeat: Infinity, ease: "linear" }}
        />
      )}
    </div>
  );
}

function ScenarioLab() {
  const [flash, setFlash] = useState<LiveDetection | null>(null);

  const trigger = (ruleId: string) => {
    const detection = injectScenario(ruleId);
    if (!detection) return;
    setFlash(detection);
    window.setTimeout(() => {
      setFlash((cur) => (cur === detection ? null : cur));
    }, 5000);
  };

  return (
    <section className="scenario-lab">
      <div className="scenario-lab-panel">
        <div className="scenario-lab-head">
          <span className="eyebrow">Customize this demo</span>
          <h2>Try a detection scenario</h2>
          <p>
            Fire one of the real detectors against the replayed capture. It's recorded into the
            console's alert history exactly like a live finding would be — enter the console
            after and it'll be sitting at the top of the table.
          </p>
        </div>
        <div className="scenario-chips">
          {SCENARIOS.map((s) => (
            <button
              key={s.ruleId}
              type="button"
              className="scenario-chip"
              style={{ ["--chip-sev" as string]: `var(--${s.severity})` }}
              onClick={() => trigger(s.ruleId)}
            >
              {s.label}
            </button>
          ))}
        </div>
        <AnimatePresence>
          {flash && (
            <motion.div
              className="scenario-flash"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.35 }}
            >
              <span className={`sev-pill sev-${flash.severity}`}>{flash.severity}</span>
              <strong>{flash.name}</strong>
              <span>{flash.description}</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}

export function Landing() {
  const packetsPerSec = useSimulatedReadout(1840, 420);
  const activeFlows = useSimulatedReadout(11, 6);

  return (
    <div className="landing">
      <nav className="landing-nav">
        <span className="landing-wordmark">
          <ScopeIcon size={20} />
          <span>NIDS</span>
        </span>
        <div className="landing-nav-links">
          <ThemeSwitcher />
          <a className="text-link" href={REPO_URL} target="_blank" rel="noreferrer">
            <GithubMarkIcon size={15} />
            Source
          </a>
          <Link to="/login" className="btn btn-primary">
            Enter console
            <ArrowRightIcon size={14} />
          </Link>
        </div>
      </nav>

      <motion.header className="hero" initial="hidden" animate="visible" variants={container}>
        <div className="hero-copy">
          <motion.span className="eyebrow" variants={item}>
            [ Live product demo ]
          </motion.span>
          <motion.h1 variants={item}>Every packet, weighed twice.</motion.h1>
          <motion.p variants={item}>
            NIDS is a hybrid signature + ML intrusion detection system — YAML rules judge
            traffic against what's already known, an Isolation Forest judges it against what's
            normal. This console runs that exact detection engine, replaying a recorded capture
            live in your browser.
          </motion.p>
          <motion.div className="hero-actions" variants={item}>
            <Link to="/login" className="btn btn-primary">
              Enter the console
              <ArrowRightIcon size={14} />
            </Link>
            <a className="btn btn-ghost" href={REPO_URL} target="_blank" rel="noreferrer">
              <GithubMarkIcon size={15} />
              View source
            </a>
          </motion.div>
          <motion.p className="hero-meta" variants={item}>
            Built solo, end to end — capture → detection → alerting → dashboard.
          </motion.p>
        </div>

        <motion.div className="hero-panel" variants={item}>
          <div className="hero-panel-head">
            <span className="eyebrow" style={{ color: "var(--muted)" }}>
              Signal monitor
            </span>
            <span className="hero-panel-dot" />
          </div>
          <SignalScope variant="wave" />
          <div className="hero-readouts">
            <div className="hero-readout">
              <div className="hero-readout-value">{packetsPerSec.toLocaleString()}</div>
              <div className="hero-readout-label">Packets / sec</div>
            </div>
            <div className="hero-readout">
              <div className="hero-readout-value">{activeFlows}</div>
              <div className="hero-readout-label">Active flows</div>
            </div>
            <div className="hero-readout">
              <div className="hero-readout-value">9</div>
              <div className="hero-readout-label">Rules loaded</div>
            </div>
          </div>
          <div className="hero-panel-note">Simulated telemetry — for feel, not fact</div>
        </motion.div>
      </motion.header>

      <section className="pipeline">
        <div className="pipeline-heading">
          <h2>How a packet gets flagged</h2>
        </div>
        <PipelineTrack />
        <div className="pipeline-steps">
          {PIPELINE.map((step, i) => (
            <motion.div
              key={step.n}
              className="pipeline-step"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 * i, ease: [0.16, 1, 0.3, 1] }}
            >
              <span className="pipeline-step-icon">
                <step.icon size={17} />
              </span>
              <span className="pipeline-step-number">{step.n}</span>
              <h3>{step.title}</h3>
              <p>{step.body}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="features">
        <div className="feature-grid">
          {FEATURES.map((f, i) => (
            <motion.div
              key={f.title}
              className="feature-card"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.06 * i, ease: [0.16, 1, 0.3, 1] }}
            >
              <span className="feature-card-icon">
                <f.icon size={20} />
              </span>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="tech-stack">
        <span className="eyebrow tech-stack-label">Under the hood</span>
        <div className="tech-chips">
          {TECH_STACK.map((t) => (
            <span key={t} className="tech-chip">
              {t}
            </span>
          ))}
        </div>
      </section>

      <ScenarioLab />

      <footer className="landing-footer">
        <span>Synthetic, replayed traffic — not a live network feed.</span>
        <div className="landing-footer-links">
          <a href={REPO_URL} target="_blank" rel="noreferrer">
            Source on GitHub ↗
          </a>
          <a href={PORTFOLIO_URL} target="_blank" rel="noreferrer">
            Part of Abhishek Bobade's portfolio ↗
          </a>
        </div>
      </footer>
    </div>
  );
}
