import type { Graph, Lens } from "@kumomiru/graph";
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

/**
 * Convert a normalized Graph into Cytoscape elements.
 *
 * - Containment becomes Cytoscape compound nesting via `data.parent`, which is
 *   what makes the map read like a real architecture diagram.
 * - Every node carries its kumomiru `type` and a `container` flag for styling.
 * - Edges carry their `lens` so the lens toggle is just a style/filter switch.
 */
export function graphToElements(graph: Graph): ElementDefinition[] {
  const nodes: ElementDefinition[] = graph.nodes.map((n) => ({
    group: "nodes",
    data: {
      id: n.id,
      label: n.name || n.type,
      kind: n.type,
      container: isContainer(n.type),
      ...(n.parent ? { parent: n.parent } : {}),
    },
  }));

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
