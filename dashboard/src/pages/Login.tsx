import { motion } from "framer-motion";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowLeftIcon, LockIcon, ScopeIcon } from "../components/icons";
import { SignalScope } from "../components/SignalScope";
import { setDemoAuthed } from "../demoAuth";
import "./Login.css";

/**
 * A decorative access gate — there's no real backend behind this demo
 * (see demoStore.ts), so nothing here actually authenticates anyone.
 * It exists to make the Landing → Console handoff feel like a real
 * product instead of a bare "click here for the dashboard" link.
 */
export function Login() {
  const navigate = useNavigate();
  const [operatorId, setOperatorId] = useState("");
  const [accessKey, setAccessKey] = useState("");
  const [status, setStatus] = useState<"idle" | "verifying">("idle");

  const enter = () => {
    setDemoAuthed(true);
    navigate("/dashboard");
  };

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("verifying");
    window.setTimeout(enter, 650);
  };

  return (
    <div className="login-page">
      <div className="login-backdrop">
        <SignalScope variant="radar" />
      </div>
      <div className="login-vignette" />

      <Link to="/" className="login-back">
        <ArrowLeftIcon size={14} />
        Back to overview
      </Link>

      <motion.div
        className="login-card"
        initial={{ opacity: 0, y: 16, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="login-mark">
          <ScopeIcon size={22} />
          <span>NIDS Console</span>
        </div>

        <div>
          <h1>Access console</h1>
          <p className="login-copy">
            This is a public product demo — no account exists behind it. Enter anything below,
            or skip straight through.
          </p>
        </div>

        <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <label className="login-field">
            Operator ID
            <input
              value={operatorId}
              onChange={(e) => setOperatorId(e.target.value)}
              placeholder="operator@nids.local"
              autoComplete="off"
            />
          </label>
          <label className="login-field">
            Access key
            <input
              type="password"
              value={accessKey}
              onChange={(e) => setAccessKey(e.target.value)}
              placeholder="••••••••"
              autoComplete="off"
            />
          </label>

          <button type="submit" className="btn btn-primary login-submit" disabled={status === "verifying"}>
            <LockIcon size={15} />
            {status === "verifying" ? "Verifying…" : "Authenticate"}
          </button>
        </form>

        <span className="login-status">
          {status === "verifying" ? "Establishing session…" : " "}
        </span>

        <button type="button" className="login-skip" onClick={enter}>
          Skip — quick access →
        </button>
      </motion.div>
    </div>
  );
}
