interface Props {
  connected: boolean;
}

export function ConnectionBadge({ connected }: Props) {
  return (
    <span className={`badge ${connected ? "badge-ok" : "badge-down"}`}>
      <span className="dot" />
      {connected ? "Live feed connected" : "Reconnecting…"}
    </span>
  );
}
