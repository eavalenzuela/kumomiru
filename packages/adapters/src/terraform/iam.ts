import {
  analyzeAssumeRole,
  type AnalyzedPrincipal,
  type AssumeTrustEntry,
  type IamAnalysisResult,
} from "../analysis/iam.js";
import type { PolicyStatement } from "../analysis/policy.js";
import type { TfState } from "./state-schema.js";

/**
 * Terraform IAM projection. DESIGN.md §3 is explicit that IAM is an *analysis
 * pass, not an adapter* — one shared brain (`analyzeAssumeRole`) regardless of
 * ingestion source. The live adapter already feeds it; this module lets the
 * Terraform adapter feed it too, so a `.tfstate` map gets the same `can-assume`
 * edges and external-can-assume findings.
 *
 * Trust comes from each role's `assume_role_policy`. Identity statements come
 * from inline policies we can see in state (`inline_policy` blocks on the
 * role/user, and standalone `aws_iam_role_policy` / `aws_iam_user_policy`
 * resources). Managed-policy *documents* are usually not in state, so internal
 * edges may be under-reported — deliberately, per the design's "be correct about
 * the simple cases and honest about the rest". External exposures need only the
 * trust side, which state always carries, so the flagship finding is reliable.
 *
 * Unlike the IAM API (which URL-encodes policy documents), Terraform stores them
 * as plain JSON strings, so parsing is a bare `JSON.parse`.
 */

/** A role/user node projected from Terraform state for the IAM pass. */
export interface TfIamNode {
  /** Node id (ARN). */
  id: string;
  account: string;
  /** Role/user name (used to join standalone inline policies). */
  name: string;
  /** Raw AWS id from state (equals the name for roles/users). */
  rawId: string;
  kind: "role" | "user";
  /** The resource's attribute bag (holds assume_role_policy, inline_policy). */
  attrs: Record<string, unknown>;
}

export function buildTerraformIam(
  state: TfState,
  iamNodes: TfIamNode[],
  selfAccount: string,
  accountNode: string,
): IamAnalysisResult {
  return analyzeAssumeRole(buildTerraformPrincipals(state, iamNodes), selfAccount, accountNode);
}

/** The principal set (roles + users with identity/trust) for both IAM passes. */
export function buildTerraformPrincipals(
  state: TfState,
  iamNodes: TfIamNode[],
): AnalyzedPrincipal[] {
  // Identity statements keyed by subject name (a role/user may be named by name
  // or raw id in the joining resource).
  const identityByName = new Map<string, PolicyStatement[]>();
  const addIdentity = (name: string, stmts: PolicyStatement[]): void => {
    if (!name || stmts.length === 0) return;
    const cur = identityByName.get(name) ?? [];
    cur.push(...stmts);
    identityByName.set(name, cur);
  };

  // Standalone inline-policy resources (aws_iam_role_policy / _user_policy).
  for (const resource of state.resources) {
    if (resource.mode !== "managed") continue;
    const subjectKey =
      resource.type === "aws_iam_role_policy"
        ? "role"
        : resource.type === "aws_iam_user_policy"
          ? "user"
          : undefined;
    if (!subjectKey) continue;
    for (const inst of resource.instances) {
      const a = inst.attributes;
      const subject = refName(a[subjectKey]);
      if (subject) addIdentity(subject, statementsFromDoc(a["policy"]));
    }
  }

  // Inline-policy blocks carried directly on the role/user resource.
  for (const n of iamNodes) {
    for (const block of asArray<Record<string, unknown>>(
      n.attrs["inline_policy"],
    )) {
      if (block && typeof block === "object") {
        addIdentity(n.name, statementsFromDoc(block["policy"]));
      }
    }
  }

  const principals: AnalyzedPrincipal[] = iamNodes.map((n) => {
    const identity = [
      ...(identityByName.get(n.name) ?? []),
      ...(identityByName.get(n.rawId) ?? []),
    ];
    if (n.kind === "role") {
      return {
        id: n.id,
        account: n.account,
        kind: "role" as const,
        identity,
        trust: trustEntriesFromDoc(n.attrs["assume_role_policy"]),
      };
    }
    return { id: n.id, account: n.account, kind: "user" as const, identity };
  });

  return principals;
}

// --- policy-document helpers -------------------------------------------------

function asArray<T>(v: unknown): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? (v as T[]) : [v as T];
}

/** A role/user reference may be a name, an id, or an ARN — extract the name. */
function refName(v: unknown): string {
  if (typeof v !== "string" || v === "") return "";
  if (v.startsWith("arn:")) {
    const resource = v.split(":").slice(5).join(":");
    const slash = resource.lastIndexOf("/");
    return slash === -1 ? resource : resource.slice(slash + 1);
  }
  return v;
}

function parseDoc(v: unknown): { Statement?: unknown } | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  try {
    return JSON.parse(v) as { Statement?: unknown };
  } catch {
    return undefined;
  }
}

/** Project an identity policy document to evaluable PolicyStatements. */
function statementsFromDoc(v: unknown): PolicyStatement[] {
  const parsed = parseDoc(v);
  const out: PolicyStatement[] = [];
  for (const raw of asArray<Record<string, unknown>>(parsed?.Statement)) {
    const condition = raw["Condition"];
    out.push({
      effect: raw["Effect"] === "Deny" ? "Deny" : "Allow",
      ...(raw["Action"] ? { actions: asArray<string>(raw["Action"]) } : {}),
      ...(raw["NotAction"]
        ? { notActions: asArray<string>(raw["NotAction"]) }
        : {}),
      ...(raw["Resource"]
        ? { resources: asArray<string>(raw["Resource"]) }
        : {}),
      ...(raw["NotResource"]
        ? { notResources: asArray<string>(raw["NotResource"]) }
        : {}),
      ...(condition ? { conditionKeys: conditionKeysOf(condition) } : {}),
    });
  }
  return out;
}

/** Parse a role's trust policy into the trust entries the IAM pass evaluates. */
function trustEntriesFromDoc(v: unknown): AssumeTrustEntry[] {
  const parsed = parseDoc(v);
  const out: AssumeTrustEntry[] = [];
  for (const raw of asArray<Record<string, unknown>>(parsed?.Statement)) {
    const effect = raw["Effect"] === "Deny" ? "Deny" : "Allow";
    const conditionKeys = conditionKeysOf(raw["Condition"]);
    const principal = raw["Principal"];
    // `"Principal": "*"` (bare public) is a string, not an object.
    if (principal === "*") {
      out.push({ principalValue: "*", type: "aws", effect });
      continue;
    }
    if (!principal || typeof principal !== "object") continue;
    for (const [key, value] of Object.entries(
      principal as Record<string, unknown>,
    )) {
      const type =
        key === "Service" ? "service" : key === "Federated" ? "federated" : "aws";
      for (const pv of asArray<string>(value)) {
        if (typeof pv === "string") {
          out.push({
            principalValue: pv,
            type,
            effect,
            ...(conditionKeys.length ? { conditionKeys } : {}),
          });
        }
      }
    }
  }
  return out;
}

function conditionKeysOf(condition: unknown): string[] {
  if (!condition || typeof condition !== "object") return [];
  const keys = new Set<string>();
  for (const byOp of Object.values(condition as Record<string, unknown>)) {
    if (byOp && typeof byOp === "object") {
      for (const k of Object.keys(byOp as Record<string, unknown>)) keys.add(k);
    }
  }
  return [...keys];
}
