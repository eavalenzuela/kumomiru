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
  /** One row per (rule, applicable resource), plus Security Hub rows (see below). */
  results: RuleResult[];
  /** Rules skipped because a required capability was absent. */
  notAssessedRules: string[];
  /** Native rule findings dropped because Security Hub reported the same control on the same resource. */
  supersededFindings: string[];
}

/** Synthetic resource id for a Security Hub-covered control with no failures. */
export const SECURITYHUB_COVERAGE_TYPE = "aws::securityhub::control";

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
  const supersededFindings: string[] = [];

  // --- Security Hub feed → rule results and supersede set -------------------
  // Security Hub's verdict on a control it reported is authoritative for that
  // account/region: FAILED findings become fail rows on their resource; a
  // covered control with no FAILED finding gets one synthetic pass row so the
  // roll-up sees it as assessed. Native findings for the same (control,
  // resource) are dropped in favour of the feed's, which carries the console
  // id. Native rule *results* still run and are stored; controlStatuses
  // prefers feed rows per control.
  const shFailed = new Map<string, Set<string>>(); // control → resource ids
  for (const f of graph.findings) {
    if (f.source !== "securityhub") continue;
    for (const c of f.controls ?? []) {
      if (c.framework !== "fsbp") continue;
      const resource = f.nodeId ?? (f.evidence?.["resourceIds"] as string[] | undefined)?.[0] ?? `securityhub:${c.id}`;
      shFailed.set(c.id, new Set([...(shFailed.get(c.id) ?? []), resource]));
      results.push({ ruleId: `securityhub.${c.id}`, resourceId: resource, resourceType: f.resourceType ?? "unknown", status: "fail" });
    }
  }
  for (const c of graph.meta.securityHubControls ?? []) {
    if (!shFailed.has(c)) {
      results.push({ ruleId: `securityhub.${c}`, resourceId: `securityhub:${c}`, resourceType: SECURITYHUB_COVERAGE_TYPE, status: "pass" });
    }
  }

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
      const superseded = rule.controls.some((c) => c.framework === "fsbp" && shFailed.get(c.id)?.has(n.id));
      if (superseded) {
        supersededFindings.push(findingId(rule.id, n.id));
        continue;
      }
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

  return { findings: [...findings, ...ruleFindings], results, notAssessedRules, supersededFindings };
}

function row(ruleId: string, n: CloudNode, status: RuleResult["status"]): RuleResult {
  return { ruleId, resourceId: n.id, resourceType: n.type, status };
}
