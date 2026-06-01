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
  }

  for (const node of graph.nodes) {
    if (node.parent !== undefined && !nodeIds.has(node.parent)) {
      problems.push(`node ${node.id} has unknown parent: ${node.parent}`);
    }
  }

  for (const finding of graph.findings) {
    if (finding.nodeId !== undefined && !nodeIds.has(finding.nodeId)) {
      problems.push(
        `finding ${finding.id} references unknown node: ${finding.nodeId}`,
      );
    }
  }

  return problems;
}
