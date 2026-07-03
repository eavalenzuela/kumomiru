import type { Finding } from "@kumomiru/graph";

interface FindingsPanelProps {
  findings: Finding[];
  onSelect?: (nodeId: string) => void;
}

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Severities in display order, for the summary chips. */
const SEVERITIES: Finding["severity"][] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Sidebar list of security findings, most severe first. */
export function FindingsPanel({ findings, onSelect }: FindingsPanelProps) {
  if (findings.length === 0) {
    return <p className="findings-empty">No findings.</p>;
  }
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  // Per-severity counts so the risk profile is legible before reading the list.
  const counts = new Map<Finding["severity"], number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  return (
    <>
      <div className="findings-summary" aria-label="Findings by severity">
        {SEVERITIES.filter((s) => counts.get(s)).map((s) => (
          <span key={s} className={`sev-chip sev-${s}`}>
            {counts.get(s)} {s}
          </span>
        ))}
      </div>
      <ul className="findings">
        {sorted.map((f) => (
          <li
            key={f.id}
            className={`finding sev-${f.severity}`}
            onClick={() => f.nodeId && onSelect?.(f.nodeId)}
          >
            <span className="sev-tag">{f.severity}</span>
            <div>
              <div className="finding-title">{f.title}</div>
              <div className="finding-detail">{f.detail}</div>
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}
