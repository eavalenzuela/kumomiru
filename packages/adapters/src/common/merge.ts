import type { Graph, GraphMeta } from "@kumomiru/graph";

/**
 * Merge several graphs of the same account into one — the scheduled scanner
 * produces one `global` (IAM) graph plus one `regional` graph per region and
 * stitches them here.
 *
 * Nodes, edges, and findings are deduplicated by id, first occurrence wins.
 * That is what makes the shared containers line up: every regional graph
 * carries the same `aws::account::<id>` node, and it collapses to one. Order is
 * preserved (containers first, then resources in input order) so the output is
 * deterministic for a given input order.
 */
export function mergeGraphs(
  graphs: readonly Graph[],
  meta: Omit<GraphMeta, "provider">,
): Graph {
  const nodes = new Map<string, Graph["nodes"][number]>();
  const edges = new Map<string, Graph["edges"][number]>();
  const findings = new Map<string, Graph["findings"][number]>();
  const capabilities = new Set<string>(meta.capabilities ?? []);
  const feeds = new Set<string>(meta.feeds ?? []);
  const shControls = new Set<string>(meta.securityHubControls ?? []);
  for (const g of graphs) {
    for (const c of g.meta.capabilities ?? []) capabilities.add(c);
    for (const f of g.meta.feeds ?? []) feeds.add(f);
    for (const c of g.meta.securityHubControls ?? []) shControls.add(c);
    for (const n of g.nodes) if (!nodes.has(n.id)) nodes.set(n.id, n);
    for (const e of g.edges) if (!edges.has(e.id)) edges.set(e.id, e);
    for (const f of g.findings) if (!findings.has(f.id)) findings.set(f.id, f);
  }
  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    findings: [...findings.values()],
    meta: {
      ...meta,
      provider: "aws",
      capabilities: [...capabilities].sort(),
      ...(feeds.size ? { feeds: [...feeds].sort() } : {}),
      ...(shControls.size ? { securityHubControls: [...shControls].sort() } : {}),
    },
  };
}
