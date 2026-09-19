import type { PolicyPrincipal, PolicyStatement } from "../analysis/policy.js";

/**
 * Project an IAM policy document (identity, trust, or resource policy) to the
 * evaluable `PolicyStatement` shape. Accepts the raw JSON string AWS returns,
 * the URL-encoded form IAM uses for inline documents, or an already-parsed
 * object (Terraform state). Malformed input yields no statements — a broken
 * document must never grant access by accident.
 *
 * Shared by the SDK client and the Terraform adapter so every source feeds
 * the analysis passes identically.
 */
export function projectPolicyDocument(doc: unknown): PolicyStatement[] {
  const parsed = parsePolicyDoc(doc) as { Statement?: unknown } | undefined;
  const out: PolicyStatement[] = [];
  for (const raw of asArray(parsed?.Statement)) {
    if (!raw || typeof raw !== "object") continue;
    const s = raw as Record<string, unknown>;
    const condition = s["Condition"];
    const principals = projectPrincipals(s["Principal"], s["NotPrincipal"]);
    out.push({
      effect: s["Effect"] === "Deny" ? "Deny" : "Allow",
      ...(s["Action"] ? { actions: asArray(s["Action"] as string) } : {}),
      ...(s["NotAction"] ? { notActions: asArray(s["NotAction"] as string) } : {}),
      ...(s["Resource"] ? { resources: asArray(s["Resource"] as string) } : {}),
      ...(s["NotResource"] ? { notResources: asArray(s["NotResource"] as string) } : {}),
      ...(condition ? { conditionKeys: conditionKeysOf(condition) } : {}),
      ...(principals ? { principals } : {}),
    });
  }
  return out;
}

function projectPrincipals(principal: unknown, notPrincipal: unknown): PolicyPrincipal[] | undefined {
  if (notPrincipal !== undefined) {
    // NotPrincipal grants to everyone except — treat as public for exposure.
    return [{ type: "*", value: "*", negated: true }];
  }
  if (principal === undefined) return undefined;
  if (principal === "*") return [{ type: "*", value: "*" }];
  if (!principal || typeof principal !== "object") return undefined;
  const out: PolicyPrincipal[] = [];
  for (const [key, value] of Object.entries(principal as Record<string, unknown>)) {
    const type: PolicyPrincipal["type"] =
      key === "Service" ? "service" : key === "Federated" ? "federated" : key === "CanonicalUser" ? "canonical-user" : "aws";
    for (const v of asArray(value as string)) {
      if (typeof v === "string") out.push(v === "*" && type === "aws" ? { type: "*", value: "*" } : { type, value: v });
    }
  }
  return out;
}

/** Collect the condition keys (e.g. sts:ExternalId) from a Condition block. */
export function conditionKeysOf(condition: unknown): string[] {
  if (!condition || typeof condition !== "object") return [];
  const keys = new Set<string>();
  for (const byOp of Object.values(condition as Record<string, unknown>)) {
    if (byOp && typeof byOp === "object") {
      for (const k of Object.keys(byOp as Record<string, unknown>)) keys.add(k);
    }
  }
  return [...keys];
}

/**
 * Parse a policy document that may be an object, a JSON string, or a
 * URL-encoded JSON string (as IAM returns inline documents).
 */
export function parsePolicyDoc(doc: unknown): unknown {
  if (doc === undefined || doc === null) return undefined;
  if (typeof doc === "object") return doc;
  if (typeof doc !== "string") return undefined;
  const text = doc.trim();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    try {
      return JSON.parse(decodeURIComponent(text));
    } catch {
      return undefined;
    }
  }
}

export const asArray = <T>(v: T | T[] | undefined): T[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];
