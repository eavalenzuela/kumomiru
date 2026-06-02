import type { Graph, CloudNode } from "./types.js";

/**
 * Topology-preserving redaction for shareable exports (DESIGN.md §6B: "Exported
 * .json maps are confidential. Offer a redacted export mode.").
 *
 * The goal is to share the SHAPE of an environment — its containment hierarchy
 * and the three lenses — without leaking the data *values* that make a map
 * sensitive. So we strip:
 *
 *   - IP addresses (public/private) and CIDR blocks — addressing detail,
 *   - tag VALUES (keys are kept; they describe structure, values often carry
 *     owner emails / cost codes / environment specifics),
 *   - any attribute already redacted to a secret marker is left as the marker
 *     (it never held a value to begin with).
 *
 * Deliberately NOT removed: node ids/ARNs, names, types, account/region, and
 * the edge set — those ARE the architecture, and removing them would gut the
 * picture (and break referential integrity, since ids are edge endpoints).
 * Redaction is about values, not anonymisation; callers who need full
 * anonymisation should layer it on top.
 *
 * Pure: returns a new Graph, never mutates the input.
 */

/** Attribute keys whose values are addressing detail we strip when redacting. */
const SENSITIVE_ATTR_KEYS = new Set(["publicIp", "privateIp", "cidrBlock"]);

function redactNode(node: CloudNode): CloudNode {
  const attributes: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node.attributes)) {
    if (SENSITIVE_ATTR_KEYS.has(key)) continue;
    attributes[key] = value;
  }
  const tags: Record<string, string> = {};
  for (const key of Object.keys(node.tags)) {
    // Keep the key (structure), drop the value (potential data).
    tags[key] = "[redacted]";
  }
  return { ...node, tags, attributes };
}

export function redactGraph(graph: Graph): Graph {
  return {
    ...graph,
    nodes: graph.nodes.map(redactNode),
    // Edges carry relationships/ports, not data values — kept as-is.
    edges: graph.edges.map((e) => ({ ...e })),
    findings: graph.findings.map((f) => ({ ...f })),
    meta: { ...graph.meta },
  };
}
