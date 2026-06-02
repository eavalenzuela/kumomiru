/**
 * The IAM assume-role analysis pass — the shared "brain" the design calls for
 * (DESIGN.md §3): IAM is an *analysis pass, not an adapter*. It runs after node
 * collection, over the assembled principal set, and emits `lens:'iam'` edges.
 * The same module runs regardless of ingestion source (live AWS, Terraform,
 * Config) so there is exactly one place this logic lives.
 *
 * Scope for 1.0 is the assume-role graph only (trust ∩ identity). Escalation
 * taxonomy and Access Analyzer ingestion are later increments.
 *
 * The single most important correctness rule (DESIGN.md §5): a `can-assume`
 * edge requires BOTH sides —
 *   - the target role's TRUST policy permits the source principal, AND
 *   - the source principal's IDENTITY policy allows `sts:AssumeRole` on the
 *     target.
 * Checking only the trust side (the common mistake, and what the first cut of
 * the live adapter did) invents edges that don't exist.
 *
 * External principals are the exception, and deliberately so: we cannot read an
 * identity policy that lives in another account, so for an externally-trusted
 * principal the trust side alone is the exposure — the IAM analog of internet
 * ingress. Those edges are flagged `identityUnverified` and raise a finding.
 */

import type { CloudNode, CloudEdge, Finding } from "@kumomiru/graph";
import { evaluate, type PolicyStatement } from "./policy.js";

const ASSUME_ACTION = "sts:AssumeRole";

/** One principal entry from a role's trust policy. */
export interface AssumeTrustEntry {
  /** ARN, account id, account root ARN, or `"*"`. */
  principalValue: string;
  /** "aws" | "service" | "federated". */
  type: string;
  /** Defaults to Allow; a Deny entry never produces an edge. */
  effect?: "Allow" | "Deny";
  /** Condition keys gating the trust (e.g. sts:ExternalId, MFA). */
  conditionKeys?: string[];
}

/** A principal in the assembled node set, with the policy facts we evaluate. */
export interface AnalyzedPrincipal {
  /** Node id (ARN). */
  id: string;
  account: string;
  kind: "role" | "user";
  /** This principal's identity-policy statements. */
  identity: PolicyStatement[];
  /** Present (possibly empty) only for assumable roles. */
  trust?: AssumeTrustEntry[];
}

export interface IamAnalysisResult {
  /** External-principal nodes the pass had to synthesize (deduped). */
  nodes: CloudNode[];
  edges: CloudEdge[];
  findings: Finding[];
}

/**
 * Build the assume-role subgraph from the assembled principal set.
 *
 * @param principals every role/user node, with identity + (for roles) trust.
 * @param selfAccount the scanned account id; principals outside it are external.
 * @param externalParent node id to parent synthesized external principals under
 *   (typically the account container) so the graph stays referentially intact.
 */
export function analyzeAssumeRole(
  principals: AnalyzedPrincipal[],
  selfAccount: string,
  externalParent: string,
): IamAnalysisResult {
  const nodes = new Map<string, CloudNode>();
  const edges = new Map<string, CloudEdge>();
  const findings = new Map<string, Finding>();

  const roles = principals.filter((p) => p.trust !== undefined);

  for (const role of roles) {
    for (const entry of role.trust!) {
      // Service trust (ec2/lambda) is modeled when we add service-principal
      // nodes; an explicit Deny in a trust statement never grants assumption.
      if (entry.type === "service" || entry.effect === "Deny") continue;
      const trustConds = entry.conditionKeys ?? [];

      if (isExternalPrincipal(entry.principalValue, selfAccount)) {
        // Other account / federated / "*": trust alone is the exposure. We
        // cannot see the source's identity policy, so we don't require it.
        const sourceId = ensureExternalNode(
          nodes,
          entry.principalValue,
          externalParent,
        );
        addEdge(edges, sourceId, role.id, {
          external: true,
          trustConfirmed: true,
          identityUnverified: true,
          ...conditionAttrs(trustConds),
        });
        addExternalFinding(findings, role.id, entry.principalValue, trustConds);
        continue;
      }

      // Internal principal: require BOTH sides. The trust entry may name a
      // specific role/user ARN, or the account root (= any principal in the
      // account whose identity policy also allows the assume).
      for (const src of principals) {
        if (src.id === role.id) continue;
        if (!trustNames(entry.principalValue, src, selfAccount)) continue;
        const ev = evaluate(src.identity, ASSUME_ACTION, role.id);
        if (ev.decision !== "allow") continue; // deny / implicit-deny → no edge
        const conds = [...new Set([...trustConds, ...ev.conditionKeys])];
        addEdge(edges, src.id, role.id, {
          external: false,
          trustConfirmed: true,
          identityConfirmed: true,
          ...conditionAttrs(conds),
        });
      }
    }
  }

  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    findings: [...findings.values()],
  };
}

function conditionAttrs(conds: string[]): Record<string, unknown> {
  return conds.length ? { conditional: true, conditions: conds } : {};
}

/** Does a trust-policy principal value name this (internal) principal? */
function trustNames(
  value: string,
  principal: AnalyzedPrincipal,
  selfAccount: string,
): boolean {
  // Account root / bare account id: trusts the whole account — every principal
  // in it is a candidate (gated by its own identity policy, checked by caller).
  const acct = accountRoot(value);
  if (acct) return acct === principal.account;
  if (/^\d{12}$/.test(value)) return value === principal.account;
  // Otherwise an explicit ARN, possibly with wildcards.
  void selfAccount;
  return globEquals(value, principal.id);
}

/** A principal value is external if it names anything outside our account. */
function isExternalPrincipal(value: string, selfAccount: string): boolean {
  if (value === "*") return true; // anonymous / public
  const acct = accountRoot(value) ?? extractAccount(value);
  if (acct) return acct !== selfAccount;
  if (/^\d{12}$/.test(value)) return value !== selfAccount;
  // Federated providers (SAML/OIDC ARNs) without our account id → external.
  return true;
}

/** `arn:aws:iam::<acct>:root` → `<acct>`. */
function accountRoot(value: string): string | undefined {
  return value.match(/^arn:aws:iam::(\d{12}):root$/)?.[1];
}

function extractAccount(value: string): string | undefined {
  return value.match(/arn:aws:iam::(\d{12}):/)?.[1];
}

function globEquals(pattern: string, candidate: string): boolean {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const globbed = escaped.replace(/\\\*/g, ".*").replace(/\\\?/g, ".");
  return new RegExp(`^${globbed}$`).test(candidate);
}

/** Synthesize (once) an external-principal node for a trust source. */
function ensureExternalNode(
  nodes: Map<string, CloudNode>,
  value: string,
  parent: string,
): string {
  const id = `aws::iam::external-principal::${value}`;
  if (!nodes.has(id)) {
    const acct = accountRoot(value) ?? extractAccount(value);
    nodes.set(id, {
      id,
      type: "aws::iam::external-principal",
      name:
        value === "*"
          ? "any principal (*)"
          : acct
            ? `external-account-${acct}`
            : value,
      account: acct ?? "external",
      parent,
      tags: {},
      attributes: { external: true, principal: value },
    });
  }
  return id;
}

function addEdge(
  edges: Map<string, CloudEdge>,
  source: string,
  target: string,
  attributes: Record<string, unknown>,
): void {
  const id = `e-assume-${hashId(`${source}->${target}`)}`;
  if (!edges.has(id)) {
    edges.set(id, {
      id,
      source,
      target,
      relationship: "can-assume",
      lens: "iam",
      attributes,
    });
  }
}

function addExternalFinding(
  findings: Map<string, Finding>,
  roleId: string,
  principal: string,
  conds: string[],
): void {
  const id = `f-extassume-${hashId(`${principal}->${roleId}`)}`;
  // Ungated cross-account trust is critical; a condition (ExternalId/MFA)
  // reduces but does not eliminate the concern.
  const severity = conds.length ? "high" : "critical";
  const gate = conds.length
    ? `It is gated by condition(s): ${conds.join(", ")} — verify they are sufficient.`
    : `There is no condition (e.g. sts:ExternalId or MFA), so any principal in that party can assume it.`;
  findings.set(id, {
    id,
    severity,
    kind: "external-can-assume",
    nodeId: roleId,
    title: "External principal can assume a role",
    detail: `Role ${roleId} trusts external principal ${principal}. ${gate}`,
  });
}

/** Small stable id hash (djb2) so edge/finding ids are deterministic. */
function hashId(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (h * 33) ^ s.charCodeAt(i);
  return (h >>> 0).toString(36);
}
