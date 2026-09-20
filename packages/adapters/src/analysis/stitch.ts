import type { Graph } from "@kumomiru/graph";

/**
 * Cross-account stitching. Each account is scanned and stored on its own,
 * but the operator has told us which accounts belong to them. A principal
 * that is "external" to the scanned account yet lives in another registered
 * account is not an outsider — it is a sibling. This pass marks such
 * external-principal nodes and their edges `knownAccount: true`, and steps
 * the related findings down one severity with an explanation, without
 * removing them: cross-account trust inside the estate is still worth a
 * look, just not a critical one.
 *
 * Pure: returns a new Graph.
 */
export function stitchKnownAccounts(graph: Graph, knownAccountIds: ReadonlySet<string>): Graph {
  const known = new Set<string>();
  const nodes = graph.nodes.map((n) => {
    if (n.type !== "aws::iam::external-principal") return n;
    if (n.account === graph.meta.accountId || !knownAccountIds.has(n.account)) return n;
    known.add(n.id);
    return { ...n, name: `${n.name} (registered account)`, attributes: { ...n.attributes, knownAccount: true } };
  });
  if (known.size === 0) return graph;

  const edges = graph.edges.map((e) => (known.has(e.source) ? { ...e, attributes: { ...e.attributes, knownAccount: true } } : e));
  const knownAccountsOnEdgeTarget = new Map<string, Set<string>>();
  for (const e of edges) {
    if (!known.has(e.source)) continue;
    const acct = graph.nodes.find((n) => n.id === e.source)?.account ?? "";
    knownAccountsOnEdgeTarget.set(e.target, new Set([...(knownAccountsOnEdgeTarget.get(e.target) ?? []), acct]));
  }
  const step: Record<string, Graph["findings"][number]["severity"]> = { critical: "high", high: "medium", medium: "low", low: "info", info: "info" };
  const findings = graph.findings.map((f) => {
    if (!f.nodeId || (f.kind !== "external-can-assume" && f.kind !== "external-can-access")) return f;
    const accts = knownAccountsOnEdgeTarget.get(f.nodeId);
    if (!accts) return f;
    const mentioned = [...accts].find((a) => f.detail.includes(a));
    if (!mentioned) return f;
    return {
      ...f,
      severity: step[f.severity] ?? f.severity,
      detail: `${f.detail} Account ${mentioned} is registered in kumomiru (in-estate), so this is cross-account trust inside your own accounts rather than a third party.`,
      evidence: { ...(f.evidence ?? {}), knownAccount: mentioned },
    };
  });
  return { ...graph, nodes, edges, findings };
}
