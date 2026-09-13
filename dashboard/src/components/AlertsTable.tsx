import type { Alert, LiveDetection } from "../types";

interface Row {
  key: string;
  at: string;
  detector: string;
  severity: string;
  name: string;
  description: string;
  src: string;
  dst: string;
  confidence: number;
  live: boolean;
}

function fromAlert(a: Alert): Row {
  return {
    key: a.id,
    at: a.created_at,
    detector: a.detector,
    severity: a.severity,
    name: a.name,
    description: a.description,
    src: `${a.src_ip}:${a.src_port || "-"}`,
    dst: `${a.dst_ip}:${a.dst_port || "-"}`,
    confidence: a.confidence,
    live: false,
  };
}

function fromLive(d: LiveDetection, index: number): Row {
  return {
    key: `live-${d.at}-${index}`,
    at: d.at,
    detector: d.detector,
    severity: d.severity,
    name: d.name,
    description: d.description,
    src: d.src_ip,
    dst: `${d.dst_ip}:${d.dst_port || "-"}`,
    confidence: d.confidence,
    live: true,
  };
}

interface Props {
  alerts: Alert[];
  live: LiveDetection[];
}

export function AlertsTable({ alerts, live }: Props) {
  // Live websocket detections land before the DB round-trip completes, so
  // show them first and let persisted alerts fill in behind once fetched.
  const seenKeys = new Set<string>();
  const rows: Row[] = [];
  for (const d of live.map(fromLive)) {
    rows.push(d);
    seenKeys.add(`${d.at}|${d.src}|${d.dst}|${d.name}`);
  }
  for (const a of alerts.map(fromAlert)) {
    const dedupeKey = `${a.at}|${a.src}|${a.dst}|${a.name}`;
    if (!seenKeys.has(dedupeKey)) rows.push(a);
  }

  return (
    <section className="panel">
      <h2>Recent alerts</h2>
      {rows.length === 0 ? (
        <p className="empty">No alerts yet — start a capture or replay a pcap.</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Severity</th>
                <th>Detector</th>
                <th>Rule</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key} className={row.live ? "row-live" : undefined}>
                  <td>{new Date(row.at).toLocaleTimeString()}</td>
                  <td>
                    <span className={`sev-pill sev-${row.severity}`}>{row.severity}</span>
                  </td>
                  <td>{row.detector}</td>
                  <td title={row.description}>{row.name}</td>
                  <td className="mono">{row.src}</td>
                  <td className="mono">{row.dst}</td>
                  <td>{(row.confidence * 100).toFixed(0)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
