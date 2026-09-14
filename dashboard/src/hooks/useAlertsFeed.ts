import { useEffect, useRef, useState } from "react";
import { WS_URL } from "../api";
import { DEMO_MODE, isCapturing, tickDemoFeed } from "../demoStore";
import type { LiveDetection } from "../types";

const MAX_LIVE_ITEMS = 200;
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 15000;
const DEMO_TICK_MS = 4000;

/**
 * Subscribes to /ws/alerts and keeps a rolling buffer of the most recent
 * live detections, reconnecting with exponential backoff on drop — a
 * dashboard tab left open for hours shouldn't need a manual refresh.
 *
 * In demo mode there's no server to connect to at all — this synthesizes
 * the same shape of feed from the recorded fixture set instead, so the
 * rest of the app (AlertsTable, the "connected" badge) can't tell the
 * difference.
 */
export function useAlertsFeed(): { connected: boolean; live: LiveDetection[] } {
  // Demo mode has nothing to wait for — it's "connected" from the first
  // render, so this is initialized directly rather than set from inside
  // the effect below (which only needs to run the interval in that case).
  const [connected, setConnected] = useState(DEMO_MODE);
  const [live, setLive] = useState<LiveDetection[]>([]);
  const backoffRef = useRef(INITIAL_BACKOFF_MS);
  const closedByUsRef = useRef(false);

  useEffect(() => {
    if (DEMO_MODE) {
      const interval = setInterval(() => {
        if (!isCapturing()) return;
        setLive((prev) => [tickDemoFeed(), ...prev].slice(0, MAX_LIVE_ITEMS));
      }, DEMO_TICK_MS);
      return () => clearInterval(interval);
    }
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      socket = new WebSocket(WS_URL);

      socket.onopen = () => {
        setConnected(true);
        backoffRef.current = INITIAL_BACKOFF_MS;
      };

      socket.onmessage = (event: MessageEvent<string>) => {
        try {
          const payload = JSON.parse(event.data) as LiveDetection | { type: string };
          if (payload.type === "detection") {
            setLive((prev) => [payload as LiveDetection, ...prev].slice(0, MAX_LIVE_ITEMS));
          }
        } catch {
          // Malformed frame — ignore rather than crash the feed.
        }
      };

      socket.onclose = () => {
        setConnected(false);
        if (closedByUsRef.current) return;
        reconnectTimer = setTimeout(connect, backoffRef.current);
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
      };

      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();

    return () => {
      closedByUsRef.current = true;
      clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, []);

  return { connected, live };
}
