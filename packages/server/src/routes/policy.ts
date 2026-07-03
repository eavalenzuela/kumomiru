import type { FastifyInstance } from "fastify";

/**
 * The least-privilege read-only IAM policy for live discovery (DESIGN.md §6A:
 * "Least-privilege read-only policy is derived from exactly the API calls the
 * adapters make"). This is the single source of truth — it lists exactly the
 * read-only actions `makeSdkClient` calls and deliberately omits
 * `secretsmanager:GetSecretValue` / `ssm:GetParameter`, so "kumomiru cannot read
 * your secret values" is a property of the permission set, not a promise.
 *
 * Kept in code (not read from disk) so it ships with the server and can be
 * asserted against the SDK client in tests, keeping the two from drifting.
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
