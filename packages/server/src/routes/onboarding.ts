import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { LEAST_PRIVILEGE_POLICY } from "@kumomiru/aws";
import type { Database } from "@kumomiru/db";

/**
 * Onboarding (docs/cspm-roadmap.md Phase 5): everything an operator needs
 * to put the scan role into target accounts.
 *
 * - `GET /onboarding` — the worker's host identity (recorded by the worker at
 *   start), the estate-wide ExternalId, the scan role name, org-sync state.
 * - `GET /onboarding/stackset.yaml` — a CloudFormation template creating
 *   `KumomiruScanRole` with the generated read-only policy and a trust policy
 *   for the worker host role gated by the ExternalId. Deploy it as a StackSet
 *   to an OU (or as a stack to one account). kumomiru never deploys it.
 * - `GET /onboarding/trust-policy.json` — just the trust document, for hand
 *   setup.
 * - `POST /onboarding/org-sync` — enable/disable Organizations discovery.
 *
 * Settings keys: worker.hostIdentity, org.externalId, org.scanRoleName,
 * org.sync.enabled, org.sync.lastRun, org.sync.lastError, org.sync.orgId.
 */
export const DEFAULT_SCAN_ROLE = "KumomiruScanRole";

export function ensureExternalId(db: Database): string {
  let id = db.settings.get<string>("org.externalId");
  if (!id) {
    id = `kumomiru-${randomUUID()}`;
    db.settings.set("org.externalId", id);
  }
  return id;
}

export function registerOnboardingRoutes(app: FastifyInstance, db: Database): void {
  app.get("/onboarding", async () => {
    const host = db.settings.get<{ account: string; arn: string; recordedAt: string }>("worker.hostIdentity");
    return {
      workerHostIdentity: host ?? null,
      externalId: ensureExternalId(db),
      scanRoleName: db.settings.get<string>("org.scanRoleName") ?? DEFAULT_SCAN_ROLE,
      orgSync: {
        enabled: db.settings.get<boolean>("org.sync.enabled") ?? false,
        lastRun: db.settings.get<string>("org.sync.lastRun") ?? null,
        lastError: db.settings.get<string>("org.sync.lastError") ?? null,
        orgId: db.settings.get<string>("org.sync.orgId") ?? null,
        accounts: db.accounts.list().filter((a) => a.onboarding === "organizations").length,
      },
    };
  });

  app.get("/onboarding/trust-policy.json", async (request, reply) => {
    const host = hostRoleArn(db, request.query as Record<string, string>);
    if (!host) return reply.status(409).send({ error: "no_host_identity", message: "worker has not recorded its identity yet; pass ?hostRoleArn=" });
    return trustPolicy(host, ensureExternalId(db));
  });

  app.get("/onboarding/stackset.yaml", async (request, reply) => {
    const host = hostRoleArn(db, request.query as Record<string, string>);
    if (!host) return reply.status(409).send({ error: "no_host_identity", message: "worker has not recorded its identity yet; pass ?hostRoleArn=" });
    const roleName = db.settings.get<string>("org.scanRoleName") ?? DEFAULT_SCAN_ROLE;
    reply.header("content-type", "application/x-yaml; charset=utf-8");
    reply.header("content-disposition", 'attachment; filename="kumomiru-scan-role.yaml"');
    return renderStackSet({ hostRoleArn: host, externalId: ensureExternalId(db), roleName });
  });

  const OrgSync = z.object({ enabled: z.boolean(), scanRoleName: z.string().regex(/^[\w+=,.@-]{1,64}$/).optional() });
  app.post("/onboarding/org-sync", async (request, reply) => {
    const parsed = OrgSync.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: "invalid_org_sync", issues: parsed.error.issues });
    db.settings.set("org.sync.enabled", parsed.data.enabled);
    if (parsed.data.scanRoleName) db.settings.set("org.scanRoleName", parsed.data.scanRoleName);
    ensureExternalId(db);
    return { enabled: parsed.data.enabled, scanRoleName: db.settings.get<string>("org.scanRoleName") ?? DEFAULT_SCAN_ROLE };
  });
}

function hostRoleArn(db: Database, query: Record<string, string>): string | null {
  const q = query["hostRoleArn"];
  if (q && /^arn:aws[a-z-]*:(iam|sts)::\d{12}:/.test(q)) return toRoleArn(q);
  const host = db.settings.get<{ arn: string }>("worker.hostIdentity");
  return host?.arn ? toRoleArn(host.arn) : null;
}

/** `arn:aws:sts::123:assumed-role/Name/session` → `arn:aws:iam::123:role/Name`; role ARNs pass through. */
export function toRoleArn(arn: string): string {
  const m = arn.match(/^arn:([a-z-]+):sts::(\d{12}):assumed-role\/([^/]+)\//);
  return m ? `arn:${m[1]}:iam::${m[2]}:role/${m[3]}` : arn;
}

export function trustPolicy(hostRoleArn: string, externalId: string) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "KumomiruWorkerCanAssume",
        Effect: "Allow",
        Principal: { AWS: hostRoleArn },
        Action: "sts:AssumeRole",
        Condition: { StringEquals: { "sts:ExternalId": externalId } },
      },
    ],
  };
}

/** A CloudFormation template (YAML) for the scan role. Pure text; no CFN calls. */
export function renderStackSet(input: { hostRoleArn: string; externalId: string; roleName: string }): string {
  const policy = JSON.stringify(LEAST_PRIVILEGE_POLICY, null, 2).split("\n").map((l) => `          ${l}`).join("\n");
  const trust = JSON.stringify(trustPolicy(input.hostRoleArn, input.externalId), null, 2).split("\n").map((l) => `        ${l}`).join("\n");
  return `AWSTemplateFormatVersion: "2010-09-09"
Description: >-
  kumomiru read-only scan role. Deploy as a StackSet to every account (or OU)
  kumomiru should scan. The role can only be assumed by the kumomiru worker
  (${input.hostRoleArn}) presenting the ExternalId, and holds only
  Describe/List/Get permissions: it cannot change anything and cannot read
  secret values or object data.
Parameters:
  RoleName:
    Type: String
    Default: ${input.roleName}
    Description: Name of the scan role. Must match what kumomiru assumes.
Resources:
  KumomiruScanRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      Description: kumomiru read-only posture scanning
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
${trust}
      Policies:
        - PolicyName: KumomiruReadOnlyDiscovery
          PolicyDocument:
${policy}
      Tags:
        - Key: kumomiru
          Value: scan-role
Outputs:
  RoleArn:
    Value: !GetAtt KumomiruScanRole.Arn
`;
}
