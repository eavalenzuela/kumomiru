import type { Graph, CloudNode } from "./types.js";

/**
 * Topology-preserving redaction for shareable exports (DESIGN.md §6B: "Exported
 * .json maps are confidential. Offer a redacted export mode.").
 *
 * The goal is to share the SHAPE of an environment — its containment hierarchy
 * and the three lenses — without leaking the data *values* that make a map
 * sensitive. Attributes are filtered with an ALLOWLIST, not a denylist: a
 * denylist of a few keys (publicIp/privateIp/cidrBlock) silently leaks every
 * *new* value-bearing attribute an adapter starts emitting. Instead we keep:
 *
 *   - secret markers (`{ secretPresent: true, ... }`) — already value-free,
 *   - numbers and booleans — structural facts (ports, flags), never secrets,
 *   - a small allowlist of safe structural string/array keys (engine, runtime,
 *     instance type, policy names, …),
 *
 * and DROP everything else (free-form strings: IPs, endpoints, user data, etc.).
 * Tag values are blanked but keys kept (keys describe structure; values often
 * carry owner emails / cost codes).
 *
 * Deliberately NOT removed: node ids/ARNs, names, types, account/region, and
 * the edge set — those ARE the architecture, and removing them would gut the
 * picture (and break referential integrity, since ids are edge endpoints).
 * Redaction is about values, not anonymisation; callers who need full
 * anonymisation should layer it on top.
 *
 * Pure: returns a new Graph, never mutates the input.
 */

/** Safe structural string attributes (configuration shape, not data values). */
const SAFE_STRING_ATTR_KEYS = new Set([
  "engine",
  "runtime",
  "instanceType",
  "status",
  "protocol",
  "trustedService",
  "principal",
]);

/** Safe structural array attributes (e.g. policy/action/condition names). */
const SAFE_ARRAY_ATTR_KEYS = new Set([
  "managedPolicies",
  "actions",
  "conditions",
]);

function isSecretMarker(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string, unknown>)["secretPresent"] === true
  );
}

function redactNode(node: CloudNode): CloudNode {
  const attributes: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node.attributes)) {
    if (isSecretMarker(value)) {
      attributes[key] = value; // holds no value to begin with
    } else if (typeof value === "number" || typeof value === "boolean") {
      attributes[key] = value; // structural fact
    } else if (typeof value === "string" && SAFE_STRING_ATTR_KEYS.has(key)) {
      attributes[key] = value;
    } else if (Array.isArray(value) && SAFE_ARRAY_ATTR_KEYS.has(key)) {
      attributes[key] = value;
    }
    // else: drop — an allowlist redacts unknown value-bearing attributes by
    // default rather than leaking them.
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
