/**
 * The dataflow analysis pass — "what talks to what" (DESIGN.md §5). This is the
 * lens the design flags as hardest to infer *cleanly*, so the rule here is:
 * only emit an edge backed by an explicit, observable fact, and only between
 * nodes that actually exist. We would rather under-report than draw a
 * speculative hairball in a security tool.
 *
 * Two signals, both explicit:
 *
 *   1. Security-group reachability — when SG-X allows ingress on a port from
 *      SG-Y, every resource in SG-Y can talk to every resource in SG-X on that
 *      port. This is the "SG-allows + ports" signal, derived from observed
 *      rules (UserIdGroupPairs), not guessed.
 *
 *   2. Explicit references — a Lambda environment variable whose value names
 *      another discovered resource (by ARN, or an RDS instance by identifier).
 *      The reference is resolved to an existing node by the caller; we never
 *      store the env value itself (it may be a secret).
 *
 * Pure and side-effect-free, like the IAM pass — the same module can serve any
 * adapter that can supply these projections.
 */

import type { CloudEdge } from "@kumomiru/graph";

/** A resource and the (raw) security-group ids it belongs to. */
export interface DataflowMember {
  /** Node id of the resource. */
  id: string;
  groupIds: string[];
}

/** An ingress rule expressed as "groupId allows from sourceGroupIds on ports". */
export interface DataflowIngress {
  groupId: string;
  sourceGroupIds: string[];
  /** Human-readable port or range, e.g. "5432" or "8000-8999". */
  ports: string;
}

/** An explicit reference from one node to another (already resolved to nodes). */
export interface DataflowReference {
  from: string;
  to: string;
  /** Edge relationship, e.g. "reads-from" | "connects-to" | "references". */
  relationship: string;
  /** How the reference was found, e.g. "lambda-env". */
  via: string;
}

export interface DataflowInput {
  members: DataflowMember[];
  ingress: DataflowIngress[];
  references: DataflowReference[];
}

export interface DataflowResult {
  edges: CloudEdge[];
}

/**
 * Build the dataflow subgraph from the projected facts. Edges are deduped by
 * (source, target, port/relationship) so overlapping rules don't double-draw.
 */
export function analyzeDataflow(input: DataflowInput): DataflowResult {
  const edges = new Map<string, CloudEdge>();

  // --- signal 1: security-group reachability -------------------------------
  const membersByGroup = new Map<string, string[]>();
  for (const m of input.members) {
    for (const g of m.groupIds) {
      const list = membersByGroup.get(g) ?? [];
      list.push(m.id);
      membersByGroup.set(g, list);
    }
  }

  for (const rule of input.ingress) {
    const targets = membersByGroup.get(rule.groupId) ?? [];
    if (targets.length === 0) continue;
    for (const sourceGroup of rule.sourceGroupIds) {
      for (const src of membersByGroup.get(sourceGroup) ?? []) {
        for (const dst of targets) {
          if (src === dst) continue; // intra-host (same instance) is not flow
          addEdge(edges, src, dst, "talks-to", {
            ports: rule.ports,
            via: "security-group",
          });
        }
      }
    }
  }

  // --- signal 2: explicit references ---------------------------------------
  for (const ref of input.references) {
    if (ref.from === ref.to) continue;
    addEdge(edges, ref.from, ref.to, ref.relationship, { via: ref.via });
  }

  return { edges: [...edges.values()] };
}

function addEdge(
  edges: Map<string, CloudEdge>,
  source: string,
  target: string,
  relationship: string,
  attributes: Record<string, unknown>,
): void {
  // Port (or relationship) is part of the identity so an instance pair reachable
  // on two ports yields two distinct edges, but a duplicate rule does not.
  const discriminator = String(attributes["ports"] ?? relationship);
  const id = `e-flow-${hashId(`${source}->${target}:${discriminator}`)}`;
  if (!edges.has(id)) {
    edges.set(id, {
      id,
      source,
      target,
      relationship,
      lens: "dataflow",
      attributes,
    });
  }
}

/** Small stable id hash (djb2) so edge ids are deterministic, not random. */
function hashId(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (h * 33) ^ s.charCodeAt(i);
  return (h >>> 0).toString(36);
}
