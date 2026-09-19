import type { CloudNode, Graph } from "./types.js";
import type { SnapshotDiff } from "./lifecycle.js";

/**
 * Structural diff of two snapshots of the same account. Nodes are matched by
 * id; a node "changed" when its type, parent, tags, or attributes differ.
 * Findings are matched by id, which the adapters and rule engine keep
 * deterministic for a given (rule, resource) precisely so this works.
 *
 * `prev` may be null for the first snapshot: everything is then "added".
 */
export function diffSnapshots(prev: Graph | null, next: Graph): SnapshotDiff {
  const prevNodes = new Map((prev?.nodes ?? []).map((n) => [n.id, n]));
  const nextNodes = new Map(next.nodes.map((n) => [n.id, n]));
  const prevEdges = new Set((prev?.edges ?? []).map((e) => e.id));
  const nextEdges = new Set(next.edges.map((e) => e.id));
  const prevFindings = new Map((prev?.findings ?? []).map((f) => [f.id, f]));
  const nextFindings = new Map(next.findings.map((f) => [f.id, f]));

  const nodesAdded = [...nextNodes.values()]
    .filter((n) => !prevNodes.has(n.id))
    .map(({ id, type }) => ({ id, type }));
  const nodesRemoved = [...prevNodes.values()]
    .filter((n) => !nextNodes.has(n.id))
    .map(({ id, type }) => ({ id, type }));
  const nodesChanged: SnapshotDiff["nodesChanged"] = [];
  for (const n of nextNodes.values()) {
    const p = prevNodes.get(n.id);
    if (!p) continue;
    const changedKeys = changedNodeKeys(p, n);
    if (changedKeys.length) nodesChanged.push({ id: n.id, type: n.type, changedKeys });
  }

  const brief = (f: { id: string; severity: Graph["findings"][number]["severity"]; kind: string }) => ({
    id: f.id,
    severity: f.severity,
    kind: f.kind,
  });

  return {
    prevSnapshotId: prev?.meta.snapshotId ?? null,
    nextSnapshotId: next.meta.snapshotId ?? null,
    nodesAdded,
    nodesRemoved,
    nodesChanged,
    edgesAdded: [...nextEdges].filter((id) => !prevEdges.has(id)),
    edgesRemoved: [...prevEdges].filter((id) => !nextEdges.has(id)),
    findingsNew: [...nextFindings.values()].filter((f) => !prevFindings.has(f.id)).map(brief),
    findingsResolved: [...prevFindings.values()].filter((f) => !nextFindings.has(f.id)).map(brief),
  };
}

function changedNodeKeys(a: CloudNode, b: CloudNode): string[] {
  const keys: string[] = [];
  if (a.type !== b.type) keys.push("type");
  if (a.name !== b.name) keys.push("name");
  if ((a.parent ?? null) !== (b.parent ?? null)) keys.push("parent");
  if (stable(a.tags) !== stable(b.tags)) keys.push("tags");
  const attrKeys = new Set([...Object.keys(a.attributes), ...Object.keys(b.attributes)]);
  for (const k of attrKeys) {
    if (stable(a.attributes[k]) !== stable(b.attributes[k])) keys.push(`attributes.${k}`);
  }
  return keys;
}

/** JSON with sorted object keys so equal values serialize identically. */
function stable(v: unknown): string {
  return JSON.stringify(v, (_k, val) =>
    val && typeof val === "object" && !Array.isArray(val)
      ? Object.fromEntries(Object.entries(val as Record<string, unknown>).sort(([x], [y]) => (x < y ? -1 : 1)))
      : val,
  );
}
