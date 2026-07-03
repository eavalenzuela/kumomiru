import { GraphSchema } from "./schema.js";
import type { Graph } from "./types.js";

/**
 * Parse and validate an unknown value (e.g. a JSON export or adapter output)
 * into a Graph. Throws a ZodError with a readable path on invalid input.
 */
export function parseGraph(input: unknown): Graph {
  return GraphSchema.parse(input);
}

/** Non-throwing variant — returns a discriminated result. */
export function safeParseGraph(input: unknown) {
  return GraphSchema.safeParse(input);
}

/**
 * Structural sanity checks beyond schema validation: every edge endpoint and
 * every node `parent` must reference a node that exists, and ids must be unique.
 * Returns a list of human-readable problems (empty = valid).
 */
export function checkReferentialIntegrity(graph: Graph): string[] {
  const problems: string[] = [];
  const nodeIds = new Set<string>();

  for (const node of graph.nodes) {
    if (nodeIds.has(node.id)) {
      problems.push(`duplicate node id: ${node.id}`);
    }
    nodeIds.add(node.id);
  }

  const edgeIds = new Set<string>();
  for (const edge of graph.edges) {
    if (edgeIds.has(edge.id)) {
      problems.push(`duplicate edge id: ${edge.id}`);
    }
    edgeIds.add(edge.id);
    if (!nodeIds.has(edge.source)) {
      problems.push(`edge ${edge.id} has unknown source: ${edge.source}`);
    }
    if (!nodeIds.has(edge.target)) {
      problems.push(`edge ${edge.id} has unknown target: ${edge.target}`);
    }
    // A relationship whose endpoints are the same node is almost always a wiring
    // bug (e.g. a missing lookup falling back to the node itself), and it renders
    // as a nonsensical loop. None of the model's relationships are reflexive.
    if (edge.source === edge.target) {
      problems.push(`edge ${edge.id} is a self-loop on: ${edge.source}`);
    }
  }

  for (const node of graph.nodes) {
    if (node.parent !== undefined && !nodeIds.has(node.parent)) {
      problems.push(`node ${node.id} has unknown parent: ${node.parent}`);
    }
    // A node cannot contain itself.
    if (node.parent === node.id) {
      problems.push(`node ${node.id} is its own parent`);
    }
  }

  const findingIds = new Set<string>();
  for (const finding of graph.findings) {
    if (findingIds.has(finding.id)) {
      problems.push(`duplicate finding id: ${finding.id}`);
    }
    findingIds.add(finding.id);
    if (finding.nodeId !== undefined && !nodeIds.has(finding.nodeId)) {
      problems.push(
        `finding ${finding.id} references unknown node: ${finding.nodeId}`,
      );
    }
  }

  return problems;
}
