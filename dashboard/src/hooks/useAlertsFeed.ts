import { useEffect, useRef, useState } from "react";
import { WS_URL } from "../api";
import type { LiveDetection } from "../types";

const MAX_LIVE_ITEMS = 200;
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 15000;

/**
 * Subscribes to /ws/alerts and keeps a rolling buffer of the most recent
 * live detections, reconnecting with exponential backoff on drop — a
 * dashboard tab left open for hours shouldn't need a manual refresh.
 */
export function useAlertsFeed(): { connected: boolean; live: LiveDetection[] } {
  const [connected, setConnected] = useState(false);
  const [live, setLive] = useState<LiveDetection[]>([]);
  const backoffRef = useRef(INITIAL_BACKOFF_MS);
  const closedByUsRef = useRef(false);

  useEffect(() => {
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
