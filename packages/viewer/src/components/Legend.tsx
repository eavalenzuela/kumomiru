import type { Lens } from "@kumomiru/graph";

/** Per-lens description of what the edges mean and their color. */
const LENS_EDGE: Record<Lens, { color: string; label: string; dashed?: boolean }> =
  {
    network: { color: "#475569", label: "Network reachability" },
    iam: { color: "#7c3aed", label: "IAM can-assume / can-access" },
    dataflow: { color: "#0891b2", label: "Data flow", dashed: true },
  };

interface LegendProps {
  lens: Lens;
}

/**
 * A compact key for what the map encodes, keyed to the active lens. It explains
 * the *meaning* (edge color per lens, exposure red, finding halos, muted = not
 * in this lens) rather than enumerating every resource type — that is what makes
 * the map self-explanatory, which the thesis (ease of use) demands.
 */
export function Legend({ lens }: LegendProps) {
  const edge = LENS_EDGE[lens];
  return (
    <div className="legend" aria-label="Map legend">
      <div className="legend-row">
        <span
          className="legend-line"
          style={{
            background: edge.dashed
              ? `repeating-linear-gradient(90deg, ${edge.color} 0 6px, transparent 6px 9px)`
              : edge.color,
          }}
        />
        <span>{edge.label}</span>
      </div>
      <div className="legend-row">
        <span className="legend-line" style={{ background: "#dc2626" }} />
        <span>Internet-facing / external access</span>
      </div>
      <div className="legend-row">
        <span className="legend-halo legend-halo-critical" />
        <span>Critical / high finding</span>
      </div>
      <div className="legend-row">
        <span className="legend-swatch legend-muted" />
        <span>Not in this lens</span>
      </div>
    </div>
  );
}
