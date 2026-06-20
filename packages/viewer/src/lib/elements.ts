import type { Graph, Lens, Severity } from "@kumomiru/graph";
import type { ElementDefinition } from "cytoscape";

/** Node types that act as containers (compound parents), not leaf resources. */
const CONTAINER_TYPES = new Set([
  "aws::account",
  "aws::region",
  "aws::ec2::vpc",
  "aws::ec2::subnet",
]);

export function isContainer(type: string): boolean {
  return CONTAINER_TYPES.has(type);
}

const EXTERNAL_PRINCIPAL_TYPE = "aws::iam::external-principal";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Highest finding severity per node id. Lets the canvas surface security
 * findings (DESIGN.md §6) directly on the map — a node that is the subject of a
 * critical/high finding gets a danger halo — instead of leaving them buried in
 * the sidebar list.
 */
function worstSeverityByNode(graph: Graph): Map<string, Severity> {
  const worst = new Map<string, Severity>();
  for (const f of graph.findings) {
    if (!f.nodeId) continue;
    const current = worst.get(f.nodeId);
    if (!current || SEVERITY_RANK[f.severity] > SEVERITY_RANK[current]) {
      worst.set(f.nodeId, f.severity);
    }
  }
  return worst;
}

/**
 * Convert a normalized Graph into Cytoscape elements.
 *
 * - Containment becomes Cytoscape compound nesting via `data.parent`, which is
 *   what makes the map read like a real architecture diagram.
 * - Every node carries its kumomiru `type` and a `container` flag for styling.
 * - Edges carry their `lens` so the lens toggle is just a style/filter switch.
 */
export function graphToElements(graph: Graph): ElementDefinition[] {
  const worstSeverity = worstSeverityByNode(graph);
  const typeById = new Map(graph.nodes.map((n) => [n.id, n.type]));

  const nodes: ElementDefinition[] = graph.nodes.map((n) => {
    const sev = worstSeverity.get(n.id);
    return {
      group: "nodes",
      data: {
        id: n.id,
        label: n.name || n.type,
        kind: n.type,
        container: isContainer(n.type),
        // Highest finding severity for this node (drives the danger halo).
        ...(sev ? { sev } : {}),
        ...(n.parent ? { parent: n.parent } : {}),
      },
    };
  });

  const edges: ElementDefinition[] = graph.edges.map((e) => {
    const attrs = e.attributes ?? {};
    return {
      group: "edges",
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.relationship,
        lens: e.lens,
        // Flag internet-facing ingress so the network lens can shout about it.
        internetFacing: attrs["internetFacing"] === true,
        // Flag edges originating from an external principal — the IAM analog of
        // internet exposure (DESIGN.md §5), so the IAM lens can shout too.
        external: typeById.get(e.source) === EXTERNAL_PRINCIPAL_TYPE,
      },
    };
  });

  return [...nodes, ...edges];
}

/** Lenses present in the graph's edges, in canonical order. */
export function availableLenses(graph: Graph): Lens[] {
  const present = new Set(graph.edges.map((e) => e.lens));
  return (["network", "iam", "dataflow"] as const).filter((l) =>
    present.has(l),
  );
}
