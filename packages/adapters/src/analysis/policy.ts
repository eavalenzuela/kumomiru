/**
 * A small, focused IAM policy evaluator — just enough to decide assume-role
 * reachability correctly, not a full policy simulator.
 *
 * The design (DESIGN.md §5) is explicit: don't try to be a perfect simulator on
 * day one; be correct about the simple cases (action/ARN wildcard expansion,
 * explicit-deny precedence) and *honest* about conditions — we surface the
 * condition keys on an edge rather than guessing whether they resolve.
 *
 * This module is pure and side-effect-free; it knows nothing about AWS SDKs or
 * the graph. Both the live adapter and (later) the Terraform/Config adapters
 * feed it the same projected statements.
 */

/** Allow/Deny statement projected to exactly what we evaluate. */
export interface PolicyStatement {
  effect: "Allow" | "Deny";
  /** Actions this statement applies to. Globs (`*`, `?`) are expanded. */
  actions?: string[];
  /** Inverse of `actions`: matches every action NOT listed. */
  notActions?: string[];
  /** Resource ARNs this statement applies to. Globs are expanded. */
  resources?: string[];
  /** Inverse of `resources`. */
  notResources?: string[];
  /**
   * Condition keys present on the statement (e.g. `sts:ExternalId`,
   * `aws:MultiFactorAuthPresent`). We do NOT evaluate their values — a static
   * scan usually can't — but we carry them through so the edge can be marked
   * conditional and the user given an assumption toggle.
   */
  conditionKeys?: string[];
}

export type Decision = "allow" | "deny" | "implicit-deny";

export interface EvalResult {
  decision: Decision;
  /** Condition keys gating a matched Allow (empty for deny / implicit-deny). */
  conditionKeys: string[];
}

/**
 * Compile an IAM glob (`*` = any run, `?` = any single char) to an anchored
 * RegExp. Every regex metacharacter is escaped first, then the escaped glob
 * tokens are turned back into their regex equivalents — so an ARN's `:` `/` `.`
 * `+` are matched literally.
 */
function globToRegExp(pattern: string, flags: string): RegExp {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const globbed = escaped.replace(/\\\*/g, ".*").replace(/\\\?/g, ".");
  return new RegExp(`^${globbed}$`, flags);
}

/** IAM actions are case-insensitive (`sts:AssumeRole` == `STS:assumerole`). */
function actionMatches(stmt: PolicyStatement, action: string): boolean {
  if (stmt.actions) {
    return stmt.actions.some((a) => globToRegExp(a, "i").test(action));
  }
  if (stmt.notActions) {
    return !stmt.notActions.some((a) => globToRegExp(a, "i").test(action));
  }
  // A statement with neither Action nor NotAction constrains nothing -> matches
  // no action (a malformed/irrelevant statement should never grant access).
  return false;
}

/** Resource ARNs are matched case-sensitively. */
function resourceMatches(stmt: PolicyStatement, resource: string): boolean {
  if (stmt.resources) {
    return stmt.resources.some((r) => globToRegExp(r, "").test(resource));
  }
  if (stmt.notResources) {
    return !stmt.notResources.some((r) => globToRegExp(r, "").test(resource));
  }
  return false;
}

/**
 * Evaluate a set of identity-policy statements for one (action, resource) pair.
 *
 * Precedence follows IAM: an explicit Deny anywhere wins over everything; absent
 * a Deny, a matching Allow grants (carrying its condition keys); otherwise the
 * default is implicit deny. We only model identity policies here — resource
 * policies, permission boundaries, and SCPs are later increments (DESIGN.md §5).
 */
export function evaluate(
  statements: PolicyStatement[],
  action: string,
  resource: string,
): EvalResult {
  let allowed = false;
  let conditionKeys: string[] = [];
  for (const stmt of statements) {
    if (!actionMatches(stmt, action) || !resourceMatches(stmt, resource)) {
      continue;
    }
    if (stmt.effect === "Deny") {
      // Explicit deny is final regardless of any Allow seen before or after.
      return { decision: "deny", conditionKeys: [] };
    }
    allowed = true;
    conditionKeys = conditionKeys.concat(stmt.conditionKeys ?? []);
  }
  return allowed
    ? { decision: "allow", conditionKeys: [...new Set(conditionKeys)] }
    : { decision: "implicit-deny", conditionKeys: [] };
}
