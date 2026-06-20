import type { CloudNode, Finding, Lens } from "@kumomiru/graph";
import { humanizeType, formatValue } from "../lib/format.js";

/** One relationship touching the inspected node, resolved to the other end. */
export interface Connection {
  dir: "out" | "in";
  relationship: string;
  lens: Lens;
  otherId: string;
  otherName: string;
  /** True if this edge is an exposure edge (internet-facing or external). */
  danger: boolean;
}

interface InspectorPanelProps {
  node: CloudNode;
  findings: Finding[];
  connections: Connection[];
  onSelectNode: (id: string) => void;
  /** Spotlight every principal that can reach this node (IAM reachability). */
  onTrace?: (id: string) => void;
  onClose: () => void;
}

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Detail panel for the selected node. Shows what the map can't: the resource's
 * type/identity, its findings, its sanitized attributes and tags, and every
 * relationship it participates in (clickable to walk the graph). It reads from
 * the normalized graph model — never from a cloud SDK — and never expands a
 * secret value (attributes already arrive sanitized, e.g. `secretPresent`).
 */
export function InspectorPanel({
  node,
  findings,
  connections,
  onSelectNode,
  onTrace,
  onClose,
}: InspectorPanelProps) {
  const nodeFindings = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const attrs = Object.entries(node.attributes ?? {});
  const tags = Object.entries(node.tags ?? {});

  return (
    <div className="inspector">
      <div className="inspector-head">
        <div>
          <div className="inspector-type">{humanizeType(node.type)}</div>
          <div className="inspector-name">{node.name || node.id}</div>
        </div>
        <button
          type="button"
          className="inspector-close"
          onClick={onClose}
          aria-label="Close inspector"
          title="Close"
        >
          ✕
        </button>
      </div>

      <dl className="inspector-meta">
        <dt>ARN / id</dt>
        <dd className="mono">{node.id}</dd>
        <dt>Account</dt>
        <dd>{node.account}</dd>
        {node.region && (
          <>
            <dt>Region</dt>
            <dd>{node.region}</dd>
          </>
        )}
      </dl>

      {onTrace && (
        <button
          type="button"
          className="trace-btn"
          onClick={() => onTrace(node.id)}
          title="Highlight every principal that can reach this node over IAM edges"
        >
          ⟲ Who can reach this?
        </button>
      )}

      {nodeFindings.length > 0 && (
        <section className="inspector-section">
          <h3>Findings</h3>
          <ul className="findings">
            {nodeFindings.map((f) => (
              <li key={f.id} className={`finding sev-${f.severity}`}>
                <span className="sev-tag">{f.severity}</span>
                <div>
                  <div className="finding-title">{f.title}</div>
                  <div className="finding-detail">{f.detail}</div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {connections.length > 0 && (
        <section className="inspector-section">
          <h3>Connections</h3>
          <ul className="conn-list">
            {connections.map((c, i) => (
              <li key={`${c.dir}-${c.otherId}-${c.relationship}-${i}`}>
                <button
                  type="button"
                  className={`conn${c.danger ? " conn-danger" : ""}`}
                  onClick={() => onSelectNode(c.otherId)}
                  title={c.otherId}
                >
                  <span className={`conn-rel lens-${c.lens}`}>
                    {c.dir === "out" ? "→" : "←"} {c.relationship}
                  </span>
                  <span className="conn-other">{c.otherName}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {attrs.length > 0 && (
        <section className="inspector-section">
          <h3>Attributes</h3>
          <dl className="inspector-meta">
            {attrs.map(([k, v]) => (
              <div key={k} className="attr-row">
                <dt>{k}</dt>
                <dd className={k.toLowerCase().includes("secret") ? "secret" : ""}>
                  {formatValue(v)}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      {tags.length > 0 && (
        <section className="inspector-section">
          <h3>Tags</h3>
          <dl className="inspector-meta">
            {tags.map(([k, v]) => (
              <div key={k} className="attr-row">
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}
    </div>
  );
}
