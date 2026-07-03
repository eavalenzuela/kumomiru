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

/**
 * Forward reachability over one lens: "what can this principal reach?" — the
 * other half of DESIGN.md §5's reachability pair (the forward-subgraph question
 * to the reverse "who can reach admin?"). A breadth-first walk *forward* over
 * outgoing edges collects everything the source can ultimately reach and the
 * edges on the way — e.g. from a user: the roles it can assume, and (transitively)
 * whatever those roles can reach. Pure graph traversal; no secret is ever read.
 */
export function forwardReachable(
  graph: Graph,
  sourceId: string,
  lens: Lens,
): ReachSet {
  const outgoing = new Map<string, { edgeId: string; to: string }[]>();
  for (const e of graph.edges) {
    if (e.lens !== lens) continue;
    const list = outgoing.get(e.source);
    const entry = { edgeId: e.id, to: e.target };
    if (list) list.push(entry);
    else outgoing.set(e.source, [entry]);
  }

  const nodes = new Set<string>([sourceId]);
  const edges = new Set<string>();
  const queue: string[] = [sourceId];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const { edgeId, to } of outgoing.get(cur) ?? []) {
      edges.add(edgeId);
      if (!nodes.has(to)) {
        nodes.add(to);
        queue.push(to);
      }
    }
  }
  return { nodes: [...nodes], edges: [...edges] };
}
