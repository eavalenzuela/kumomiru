import type { FastifyInstance } from "fastify";

/**
 * The least-privilege read-only IAM policy for live discovery (DESIGN.md §6A:
 * "Least-privilege read-only policy is derived from exactly the API calls the
 * adapters make"). This is the SINGLE SOURCE OF TRUTH — it lists exactly the
 * read-only actions `makeSdkClient` calls and deliberately omits
 * `secretsmanager:GetSecretValue` / `ssm:GetParameter`, so "kumomiru cannot read
 * your secret values" is a property of the permission set, not a promise.
 *
 * `docs/least-privilege-policy.json` is GENERATED from this constant
 * (`pnpm policy:gen`); a test fails if the two drift, and another fails if any
 * action on the denylist below ever appears here.
 */
export const LEAST_PRIVILEGE_POLICY = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "KumomiruReadOnlyDiscovery",
      Effect: "Allow",
      Action: [
        "sts:GetCallerIdentity",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceAttribute",
        "rds:DescribeDBInstances",
        "lambda:ListFunctions",
        "iam:GetAccountAuthorizationDetails",
        "secretsmanager:ListSecrets",
      ],
      Resource: "*",
    },
  ],
} as const;

/**
 * Actions that must NEVER appear in the scan policy. The first two are the
 * original "cannot read your secret values" guarantee; the rest widen it to
 * "cannot read your data plane" (see docs/cspm-roadmap.md §1). Patterns are
 * matched case-insensitively as prefixes so `ssm:GetParameters` and
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
    DENIED_ACTION_PREFIXES.some((d) => a.toLowerCase().startsWith(d.toLowerCase())),
  );
}

/**
 * GET /policy/least-privilege — serve the read-only IAM policy a scan role
 * needs. The viewer offers this as a one-click download so onboarding a role is
 * trivial: attach exactly this, nothing more.
 */
export function registerPolicyRoute(app: FastifyInstance): void {
  app.get("/policy/least-privilege", async (_request, reply) => {
    reply.header(
      "content-disposition",
      'attachment; filename="kumomiru-readonly-policy.json"',
    );
    return LEAST_PRIVILEGE_POLICY;
  });
}
