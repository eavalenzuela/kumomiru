/**
 * The resource-policy analysis pass — the second half of the IAM brain.
 * `analyzeAssumeRole` answers "who can become this role"; this answers "who
 * can reach this resource" for resources that carry their own policy (S3
 * buckets, KMS keys, Lambda functions, Secrets Manager secrets, and later
 * SQS/SNS/ECR/EFS). It emits `lens:'iam'` `can-access` edges and two
 * findings:
 *
 *   - `public-resource`: a statement grants an action of interest to `*`
 *     (critical when unconditioned; high when a condition key gates it —
 *     conditions like aws:SourceArn or aws:PrincipalOrgID usually narrow it,
 *     but a static scan cannot prove that).
 *   - `external-can-access`: a statement grants to a principal in another
 *     account (high; medium when conditioned).
 *
 * Same-account principals: an account-root principal delegates to identity
 * policies, so each known principal whose identity policy allows the action
 * gets an edge (identity ∩ resource). A specific same-account ARN gets an edge
 * directly — for same-account access, a resource-policy allow suffices.
 *
 * Explicit Deny statements are not modeled here (they can only reduce access,
 * and a static reading of their conditions is unreliable); the pass errs on
 * showing an edge, which the finding text says.
 */

import type { CloudNode, CloudEdge, Finding } from "@kumomiru/graph";
import {
  evaluate,
  statementCoversAction,
  statementCoversResource,
  type PolicyStatement,
} from "./policy.js";
import type { AnalyzedPrincipal } from "./iam.js";

/** A resource whose own policy the pass should evaluate. */
export interface AccessResource {
  /** Node id (ARN). */
  id: string;
  type: string;
  account: string;
  statements: PolicyStatement[];
  /** Actions that mean "can read/use it", e.g. s3:GetObject, kms:Decrypt. */
  actions: string[];
  /**
   * Extra resource ARN forms a policy may name for this resource, e.g. an S3
   * bucket's object ARN `<bucket-arn>/*`.
   */
  resourceAliases?: string[];
}

export interface ResourceAccessResult {
  nodes: CloudNode[];
  edges: CloudEdge[];
  findings: Finding[];
}

export function analyzeResourceAccess(
  principals: AnalyzedPrincipal[],
  resources: AccessResource[],
  selfAccount: string,
  externalParent: string,
): ResourceAccessResult {
  const nodes = new Map<string, CloudNode>();
  const edges = new Map<string, CloudEdge>();
  const findings = new Map<string, Finding>();
  const byId = new Map(principals.map((p) => [p.id, p]));

  for (const res of resources) {
    const targets = [res.id, ...(res.resourceAliases ?? [])];
    for (const stmt of res.statements) {
      if (stmt.effect !== "Allow" || !stmt.principals) continue;
      const action = res.actions.find(
        (a) => statementCoversAction(stmt, a) && targets.some((t) => statementCoversResource(stmt, t)),
      );
      if (!action) continue;
      const conds = stmt.conditionKeys ?? [];

      for (const p of stmt.principals) {
        if (p.type === "service") continue;
        if (p.type === "*" || p.value === "*" || p.negated) {
          const src = ensureExternalNode(nodes, "*", externalParent);
          addEdge(edges, src, res.id, action, { public: true, external: true, ...condAttrs(conds) });
          addPublicFinding(findings, res, action, conds);
          continue;
        }
        const acct = accountOf(p.value);
        if (p.type === "federated" || p.type === "canonical-user" || (acct && acct !== selfAccount) || (!acct && !/^\d{12}$/.test(p.value))) {
          const src = ensureExternalNode(nodes, p.value, externalParent);
          addEdge(edges, src, res.id, action, { external: true, ...condAttrs(conds) });
          addExternalFinding(findings, res, p.value, action, conds);
          continue;
        }
        if (/^\d{12}$/.test(p.value) && p.value !== selfAccount) {
          const src = ensureExternalNode(nodes, p.value, externalParent);
          addEdge(edges, src, res.id, action, { external: true, ...condAttrs(conds) });
          addExternalFinding(findings, res, p.value, action, conds);
          continue;
        }
        // Same account. Root (or bare account id) → identity policies decide.
        if (isAccountRoot(p.value) || /^\d{12}$/.test(p.value)) {
          for (const pr of principals) {
            const ev = evaluate(pr.identity, action, res.id);
            const evAlias = ev.decision === "allow" ? ev : targets.slice(1).map((t) => evaluate(pr.identity, action, t)).find((e) => e.decision === "allow");
            const hit = ev.decision === "allow" ? ev : evAlias;
            if (!hit) continue;
            addEdge(edges, pr.id, res.id, action, {
              external: false,
              via: "identity+resource",
              ...condAttrs([...new Set([...conds, ...hit.conditionKeys])]),
            });
          }
          continue;
        }
        // Specific same-account ARN: resource policy alone grants.
        const direct = byId.get(p.value) ?? [...byId.values()].find((pr) => globEquals(p.value, pr.id));
        if (direct) {
          addEdge(edges, direct.id, res.id, action, { external: false, via: "resource", ...condAttrs(conds) });
        }
      }
    }
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()], findings: [...findings.values()] };
}

function condAttrs(conds: string[]): Record<string, unknown> {
  return conds.length ? { conditional: true, conditions: conds } : {};
}

function isAccountRoot(value: string): boolean {
  return /^arn:[a-z-]+:iam::\d{12}:root$/.test(value);
}

function accountOf(value: string): string | undefined {
  return value.match(/^arn:[a-z-]+:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):/)?.[1];
}

function globEquals(pattern: string, candidate: string): boolean {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\\\*/g, ".*").replace(/\\\?/g, ".")}$`).test(candidate);
}

function ensureExternalNode(nodes: Map<string, CloudNode>, value: string, parent: string): string {
  // Same id scheme as analyzeAssumeRole so the two passes share one node per principal.
  const id = `aws::iam::external-principal::${value}`;
  if (!nodes.has(id)) {
    const acct = value.match(/^arn:[a-z-]+:iam::(\d{12}):root$/)?.[1] ?? accountOf(value) ?? (/^\d{12}$/.test(value) ? value : undefined);
    nodes.set(id, {
      id,
      type: "aws::iam::external-principal",
      name: value === "*" ? "any principal (*)" : acct ? `external-account-${acct}` : value,
      account: acct ?? "external",
      parent,
      tags: {},
      attributes: { external: true, principal: value },
    });
  }
  return id;
}

function addEdge(edges: Map<string, CloudEdge>, source: string, target: string, action: string, attributes: Record<string, unknown>): void {
  const id = `e-access-${hashId(`${source}->${target}`)}`;
  if (!edges.has(id)) {
    edges.set(id, { id, source, target, relationship: "can-access", lens: "iam", attributes: { action, ...attributes } });
  }
}

function addPublicFinding(findings: Map<string, Finding>, res: AccessResource, action: string, conds: string[]): void {
  const id = `f-pubres-${hashId(res.id)}`;
  if (findings.has(id)) return;
  const gate = conds.length
    ? ` The grant is gated by condition(s) ${conds.join(", ")}; verify they actually restrict the audience.`
    : " There is no condition, so anyone on the internet can perform it.";
  findings.set(id, {
    id,
    severity: conds.length ? "high" : "critical",
    kind: "public-resource",
    nodeId: res.id,
    title: "Resource policy grants access to everyone",
    detail: `${res.id} allows ${action} to principal "*".${gate}`,
  });
}

function addExternalFinding(findings: Map<string, Finding>, res: AccessResource, principal: string, action: string, conds: string[]): void {
  const id = `f-extaccess-${hashId(`${principal}->${res.id}`)}`;
  if (findings.has(id)) return;
  const gate = conds.length ? ` Gated by condition(s) ${conds.join(", ")}.` : " There is no condition.";
  findings.set(id, {
    id,
    severity: conds.length ? "medium" : "high",
    kind: "external-can-access",
    nodeId: res.id,
    title: "External principal can access a resource",
    detail: `${res.id} allows ${action} to external principal ${principal}.${gate}`,
  });
}

function hashId(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (h * 33) ^ s.charCodeAt(i);
  return (h >>> 0).toString(36);
}
