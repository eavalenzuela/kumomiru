import type {
  CloudNode,
  ControlRef,
  Graph,
  Remediation,
  Severity,
} from "@kumomiru/graph";

export interface RuleContext {
  graph: Graph;
  /** What the producing scan collected (`DISCOVERY_CAPABILITIES`). */
  capabilities: ReadonlySet<string>;
  /** Node lookup by id. */
  node(id: string): CloudNode | undefined;
}

export type RuleOutcome =
  | { status: "pass" }
  | { status: "not-applicable" }
  | {
      status: "fail";
      detail: string;
      /** Sanitized values the rule saw; redacted on export. */
      evidence?: Record<string, unknown>;
      /** Override the rule's default severity for this resource. */
      severity?: Severity;
    };

interface RuleBase {
  /** Stable id, `<service>.<slug>`. Changing it requires `replaces`. */
  id: string;
  version: number;
  title: string;
  severity: Severity;
  /** Finding `kind` for findings this rule raises. */
  kind: string;
  controls: ControlRef[];
  remediation: Remediation;
  replaces?: string[];
}

/** A rule that evaluates resources of the given types. */
export interface CheckRule extends RuleBase {
  resourceTypes: string[];
  /** Capabilities the graph must have been collected with. */
  requires: string[];
  check(node: CloudNode, ctx: RuleContext): RuleOutcome;
  adopts?: undefined;
}

/**
 * A rule that adopts findings an adapter already emits (by `kind`), giving
 * them controls, remediation, and lifecycle without moving the detection.
 */
export interface AdoptRule extends RuleBase {
  adopts: string;
  resourceTypes?: undefined;
  requires?: undefined;
  check?: undefined;
}

export type Rule = CheckRule | AdoptRule;

export function isCheckRule(r: Rule): r is CheckRule {
  return typeof r.check === "function";
}
