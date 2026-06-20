import type { Graph, Lens } from "@kumomiru/graph";

export interface ReachSet {
  /** Every node that can reach the target (including the target). */
  nodes: string[];
  /** Every edge on a path to the target. */
  edges: string[];
}

/**
 * Reverse reachability over one lens: "who can reach this target?" — DESIGN.md
 * §6's signature view. A breadth-first walk backward over incoming edges from
 * the target collects every upstream principal and the edges connecting them
 * (e.g. for an IAM secret: the roles that can-access it, and the principals that
 * can-assume those roles, transitively). Pure graph traversal — it never
 * resolves a secret value, so it stays within the locked design decisions.
 */
export function reverseReachable(
  graph: Graph,
  targetId: string,
  lens: Lens,
): ReachSet {
  const incoming = new Map<string, { edgeId: string; from: string }[]>();
  for (const e of graph.edges) {
    if (e.lens !== lens) continue;
    const list = incoming.get(e.target);
    const entry = { edgeId: e.id, from: e.source };
    if (list) list.push(entry);
    else incoming.set(e.target, [entry]);
  }

  const nodes = new Set<string>([targetId]);
  const edges = new Set<string>();
  const queue: string[] = [targetId];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const { edgeId, from } of incoming.get(cur) ?? []) {
      edges.add(edgeId);
      if (!nodes.has(from)) {
        nodes.add(from);
        queue.push(from);
      }
    }
  }
  return { nodes: [...nodes], edges: [...edges] };
}
