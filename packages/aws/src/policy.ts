import { DISCOVERY_ACTIONS } from "./client.js";
import { PHASE3_ACTIONS } from "./collectors.js";
import { TRANCHE_B_ACTIONS } from "./collectors-b.js";
import { FEED_ACTIONS } from "./feeds.js";
import { REGION_ACTIONS } from "./regions.js";

/**
 * The least-privilege read-only IAM policy for a scan role (DESIGN.md §6A:
 * "derived from exactly the API calls the adapters make"). It is ASSEMBLED
 * from the action lists each SDK module declares next to its calls, so adding
 * a call without declaring its action is caught by the policy tests.
 *
 * `docs/least-privilege-policy.json` is generated from this (`pnpm
 * policy:gen`); a test fails if the two drift.
 */
export const LEAST_PRIVILEGE_POLICY = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "KumomiruReadOnlyDiscovery",
      Effect: "Allow",
      Action: [...new Set([...DISCOVERY_ACTIONS, ...REGION_ACTIONS, ...PHASE3_ACTIONS, ...TRANCHE_B_ACTIONS, ...FEED_ACTIONS])].sort(),
      Resource: "*",
    },
  ],
} as const;

/**
 * Actions that must NEVER appear in the scan policy. The first two are the
 * original "cannot read your secret values" guarantee; the rest widen it to
 * "cannot read your data plane" (docs/cspm-roadmap.md §1). Matched
 * case-insensitively as prefixes so `ssm:GetParameters` and
 * `ssm:GetParametersByPath` are caught by `ssm:GetParameter`.
 */
export const DENIED_ACTION_PREFIXES = [
  "secretsmanager:GetSecretValue",
  "ssm:GetParameter",
  "kms:Decrypt",
  "s3:GetObject",
  "lambda:GetFunction",
] as const;

/** Every action in the policy, flattened. */
export function policyActions(): string[] {
  return LEAST_PRIVILEGE_POLICY.Statement.flatMap((s) => [...s.Action]);
}

/** Actions in the policy that violate the denylist (expected: none). */
export function deniedActionsPresent(): string[] {
  return policyActions().filter((a) =>
    DENIED_ACTION_PREFIXES.some((d) =>
      a.toLowerCase().startsWith(d.toLowerCase()),
    ),
  );
}
