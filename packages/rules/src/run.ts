import type { CloudNode, Finding, Graph, RuleResult } from "@kumomiru/graph";

import { findingId } from "./ids.js";
import type { RuleRegistry } from "./registry.js";
import { isCheckRule, type RuleContext } from "./types.js";

export interface EvaluateOptions {
  /** Capabilities the graph was collected with. Missing → `not-assessed`. */
  capabilities: Iterable<string>;
}

export interface Evaluation {
  /** All findings: adapter findings (enriched where a rule adopts them) + rule findings. */
  findings: Finding[];
  /** One row per (rule, applicable resource). */
  results: RuleResult[];
  /** Rules skipped because a required capability was absent. */
  notAssessedRules: string[];
}

/**
 * Evaluate every registered rule against a snapshot. Pure: returns new
 * findings, never mutates the graph. Finding ids are deterministic from
 * (rule, resource) so the lifecycle layer can match across snapshots.
 */
export function evaluate(
  graph: Graph,
  registry: RuleRegistry,
  opts: EvaluateOptions,
): Evaluation {
  const capabilities = new Set(opts.capabilities);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const ctx: RuleContext = { graph, capabilities, node: (id) => byId.get(id) };

  const results: RuleResult[] = [];
  const ruleFindings: Finding[] = [];
  const notAssessedRules: string[] = [];

  // Adapter-emitted findings, enriched by an adopting rule when one exists.
  const adopters = new Map(
    registry.list().flatMap((r) => (r.adopts ? [[r.adopts, r] as const] : [])),
  );
  const findings: Finding[] = graph.findings.map((f) => {
    const rule = adopters.get(f.kind);
    if (!rule || f.ruleId) return f;
    const node = f.nodeId ? byId.get(f.nodeId) : undefined;
    return {
      ...f,
      ruleId: rule.id,
      source: f.source ?? "native",
      controls: rule.controls,
      remediation: rule.remediation,
      ...(node ? { resourceType: node.type } : {}),
    };
  });

  for (const rule of registry.list()) {
    if (!isCheckRule(rule)) continue;
    const applicable = graph.nodes.filter((n) => rule.resourceTypes.includes(n.type));
    const missing = rule.requires.filter((c) => !capabilities.has(c));
    if (missing.length > 0) {
      notAssessedRules.push(rule.id);
      for (const n of applicable) results.push(row(rule.id, n, "not-assessed"));
      continue;
    }
    for (const n of applicable) {
      const out = rule.check(n, ctx);
      results.push(row(rule.id, n, out.status));
      if (out.status !== "fail") continue;
      ruleFindings.push({
        id: findingId(rule.id, n.id),
        severity: out.severity ?? rule.severity,
        kind: rule.kind,
        nodeId: n.id,
        title: rule.title,
        detail: out.detail,
        ruleId: rule.id,
        source: "native",
        controls: rule.controls,
        remediation: rule.remediation,
        resourceType: n.type,
        ...(out.evidence ? { evidence: out.evidence } : {}),
      });
    }
  }

  return { findings: [...findings, ...ruleFindings], results, notAssessedRules };
}

function row(ruleId: string, n: CloudNode, status: RuleResult["status"]): RuleResult {
  return { ruleId, resourceId: n.id, resourceType: n.type, status };
}
