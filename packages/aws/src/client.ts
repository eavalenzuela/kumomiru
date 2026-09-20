import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import {
  EC2Client,
  DescribeVpcsCommand,
  DescribeSubnetsCommand,
  DescribeInternetGatewaysCommand,
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  DescribeInstanceAttributeCommand,
} from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import {
  IAMClient,
  GetAccountAuthorizationDetailsCommand,
  type RoleDetail,
  type UserDetail,
  type ManagedPolicyDetail,
  type PolicyDetail,
  type AttachedPolicy,
} from "@aws-sdk/client-iam";
import {
  SecretsManagerClient,
  ListSecretsCommand,
} from "@aws-sdk/client-secrets-manager";

import type {
  AwsCredentials,
  DiscoveryClient,
  DiscoveredVpc,
  DiscoveredSubnet,
  DiscoveredInternetGateway,
  DiscoveredSecurityGroup,
  DiscoveredInstance,
  DiscoveredDbInstance,
  DiscoveredFunction,
  DiscoveredSecret,
  DiscoveredRole,
  DiscoveredUser,
  PolicyStatement,
} from "@kumomiru/adapters";
import {
  auditCollector,
  ebsCollector,
  iamAccountCollector,
  kmsCollector,
  lambdaPolicyCollector,
  regionSettingsCollector,
  s3Collector,
  secretPolicyCollector,
  PHASE3_CAPABILITIES,
} from "./collectors.js";
import {
  containerCollector,
  dataCollector,
  edgeCollector,
  elbCollector,
  messagingCollector,
  rdsExtraCollector,
  routingCollector,
  scalingCollector,
} from "./collectors-b.js";
import { accessAnalyzerCollector, securityHubCollector } from "./feeds.js";

/**
 * The real, SDK-backed read-only DiscoveryClient. Every command here is
 * read-only (Describe/List/Get); there is no mutating call, by construction.
 * The client is built from borrowed credentials inside the credential broker's
 * `use` scope and is discarded with them.
 */

/**
 * The exact IAM actions `makeSdkClient` calls. The least-privilege policy is
 * generated from this list (see policy.ts), so a new SDK call must be declared
 * here or the policy tests fail. Keep it next to the calls.
 */
export const DISCOVERY_ACTIONS = [
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
] as const;
function tagsToRecord(
  tags: Array<{ Key?: string; Value?: string }> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tags ?? []) {
    if (t.Key) out[t.Key] = t.Value ?? "";
  }
  return out;
}

const USER_DATA_CONCURRENCY = 8;

/** Run `fn` over `items` with at most `limit` in flight; results discarded. */
async function mapConcurrent<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const item = items[next++]!;
      await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

/**
 * Follow a paginated List/Describe call to completion. AWS list APIs return one
 * page plus a continuation token; reading only the first page (the previous
 * behaviour of every call here except auth-details) silently truncates the map
 * in any account past the first page — the worst failure mode for a security
 * tool, since a missing resource reads as "not there". Token field names differ
 * per service (NextToken vs Marker/NextMarker), so the accessors are injected.
 */
async function paginate<TOut, TItem>(
  fetchPage: (token: string | undefined) => Promise<TOut>,
  items: (out: TOut) => TItem[] | undefined,
  nextToken: (out: TOut) => string | undefined,
): Promise<TItem[]> {
  const acc: TItem[] = [];
  let token: string | undefined;
  do {
    const out = await fetchPage(token);
    acc.push(...(items(out) ?? []));
    token = nextToken(out);
  } while (token);
  return acc;
}

export function makeSdkClient(creds: AwsCredentials): DiscoveryClient {
  const credentials = {
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    ...(creds.sessionToken ? { sessionToken: creds.sessionToken } : {}),
  };
  const region = creds.region;
  const cfg = { region, credentials };

  const ec2 = new EC2Client(cfg);
  const rds = new RDSClient(cfg);
  const lambda = new LambdaClient(cfg);
  const iam = new IAMClient(cfg);
  const sm = new SecretsManagerClient(cfg);
  const sts = new STSClient(cfg);

  // Phase 3 collectors (optional DiscoveryClient methods).
  const s3 = s3Collector(cfg, () => identity().then((i) => i.account));
  const ebs = ebsCollector(cfg);
  const kms = kmsCollector(cfg);
  const audit = auditCollector(cfg);
  const regionSettings = regionSettingsCollector(ebs, audit);
  const iamAccount = iamAccountCollector(cfg, () => identity().then((i) => i.account));
  const lambdaPolicy = lambdaPolicyCollector(cfg);
  const secretPolicy = secretPolicyCollector(cfg);
  const routing = routingCollector(cfg);
  const elbv2 = elbCollector(cfg);
  const containersB = containerCollector(cfg);
  const messaging = messagingCollector(cfg);
  const data = dataCollector(cfg);
  const scaling = scalingCollector(cfg);
  const edge = edgeCollector(cfg);
  const rdsExtra = rdsExtraCollector(cfg);
  const securityHub = securityHubCollector(cfg);
  const accessAnalyzer = accessAnalyzerCollector(cfg);

  /**
   * GetAccountAuthorizationDetails is the IAM collection backbone (DESIGN.md
   * §5): one paginated, read-only call returns every role/user with its inline
   * policies and managed-policy references, plus the managed-policy documents
   * themselves — exactly the inputs the both-sides assume-role analysis needs.
   * Memoized so roles() and users() share a single fetch per run.
   */
  let authCache: Promise<AuthDetails> | null = null;
  const authDetails = (): Promise<AuthDetails> => {
    if (!authCache) authCache = fetchAuthDetails(iam);
    return authCache;
  };

  /**
   * One GetCallerIdentity per run, shared by accountId() and partition(). The
   * partition is read off the caller's own ARN (`arn:aws-us-gov:sts::...`) so
   * node ids match the ARNs IAM returns in GovCloud / China accounts.
   */
  let identityCache: Promise<{ account: string; partition: string }> | null =
    null;
  const identity = () => {
    if (!identityCache) {
      identityCache = sts.send(new GetCallerIdentityCommand({})).then((res) => ({
        account: res.Account ?? "unknown",
        partition: res.Arn?.split(":")[1] || "aws",
      }));
    }
    return identityCache;
  };

  return {
    region: () => region,

    accountId: async () => (await identity()).account,
    partition: async () => (await identity()).partition,

    vpcs: async (): Promise<DiscoveredVpc[]> => {
      const vpcs = await paginate(
        (t) => ec2.send(new DescribeVpcsCommand(t ? { NextToken: t } : {})),
        (o) => o.Vpcs,
        (o) => o.NextToken,
      );
      // Flow logs are a per-VPC posture fact (FSBP EC2.6); one Describe call
      // covers the region. A failure leaves the attribute unset, never false.
      let flowLogged: Set<string> | undefined;
      try {
        flowLogged = await ebs.flowLogVpcIds();
      } catch {
        flowLogged = undefined;
      }
      return vpcs.map((v) => ({
        vpcId: v.VpcId ?? "",
        ...(v.CidrBlock ? { cidrBlock: v.CidrBlock } : {}),
        ...(flowLogged ? { flowLogsEnabled: flowLogged.has(v.VpcId ?? "") } : {}),
        tags: tagsToRecord(v.Tags),
      }));
    },

    subnets: async (): Promise<DiscoveredSubnet[]> => {
      const subnets = await paginate(
        (t) => ec2.send(new DescribeSubnetsCommand(t ? { NextToken: t } : {})),
        (o) => o.Subnets,
        (o) => o.NextToken,
      );
      return subnets.map((s) => ({
        subnetId: s.SubnetId ?? "",
        vpcId: s.VpcId ?? "",
        ...(s.CidrBlock ? { cidrBlock: s.CidrBlock } : {}),
        ...(s.AvailabilityZone ? { availabilityZone: s.AvailabilityZone } : {}),
        mapPublicIpOnLaunch: s.MapPublicIpOnLaunch ?? false,
        tags: tagsToRecord(s.Tags),
      }));
    },

    internetGateways: async (): Promise<DiscoveredInternetGateway[]> => {
      const gws = await paginate(
        (t) =>
          ec2.send(
            new DescribeInternetGatewaysCommand(t ? { NextToken: t } : {}),
          ),
        (o) => o.InternetGateways,
        (o) => o.NextToken,
      );
      return gws.map((g) => ({
        internetGatewayId: g.InternetGatewayId ?? "",
        ...(g.Attachments?.[0]?.VpcId
          ? { attachedVpcId: g.Attachments[0].VpcId }
          : {}),
        tags: tagsToRecord(g.Tags),
      }));
    },

    securityGroups: async (): Promise<DiscoveredSecurityGroup[]> => {
      const sgs = await paginate(
        (t) =>
          ec2.send(
            new DescribeSecurityGroupsCommand(t ? { NextToken: t } : {}),
          ),
        (o) => o.SecurityGroups,
        (o) => o.NextToken,
      );
      return sgs.map((sg) => ({
        groupId: sg.GroupId ?? "",
        ...(sg.GroupName ? { groupName: sg.GroupName } : {}),
        ...(sg.VpcId ? { vpcId: sg.VpcId } : {}),
        ingress: (sg.IpPermissions ?? []).map((p) => ({
          ...(p.FromPort !== undefined ? { fromPort: p.FromPort } : {}),
          ...(p.ToPort !== undefined ? { toPort: p.ToPort } : {}),
          ...(p.IpProtocol ? { ipProtocol: p.IpProtocol } : {}),
          cidrs: [
            ...(p.IpRanges ?? []).map((r) => r.CidrIp ?? ""),
            ...(p.Ipv6Ranges ?? []).map((r) => r.CidrIpv6 ?? ""),
          ].filter(Boolean),
          sourceGroupIds: (p.UserIdGroupPairs ?? [])
            .map((g) => g.GroupId ?? "")
            .filter(Boolean),
        })),
        tags: tagsToRecord(sg.Tags),
      }));
    },

    instances: async (): Promise<DiscoveredInstance[]> => {
      const reservations = await paginate(
        (t) =>
          ec2.send(new DescribeInstancesCommand(t ? { NextToken: t } : {})),
        (o) => o.Reservations,
        (o) => o.NextToken,
      );
      const out: DiscoveredInstance[] = [];
      for (const r of reservations) {
        for (const i of r.Instances ?? []) {
          out.push({
            instanceId: i.InstanceId ?? "",
            ...(i.SubnetId ? { subnetId: i.SubnetId } : {}),
            ...(i.InstanceType ? { instanceType: i.InstanceType } : {}),
            ...(i.PublicIpAddress ? { publicIp: i.PublicIpAddress } : {}),
            ...(i.PrivateIpAddress ? { privateIp: i.PrivateIpAddress } : {}),
            securityGroupIds: (i.SecurityGroups ?? [])
              .map((g) => g.GroupId ?? "")
              .filter(Boolean),
            ...(i.MetadataOptions?.HttpTokens ? { imdsv2Required: i.MetadataOptions.HttpTokens === "required" } : {}),
            tags: tagsToRecord(i.Tags),
          });
        }
      }
      // User-data is the #1 place plaintext secrets hide (DESIGN.md §6B) and
      // is only returned by a per-instance DescribeInstanceAttribute call. It
      // is fetched with bounded concurrency; a failure on one instance (for
      // example the attribute permission missing from an older scan role)
      // leaves that instance's userData unset rather than failing the scan —
      // the sanitizer simply has nothing to scan for it.
      await mapConcurrent(out, USER_DATA_CONCURRENCY, async (inst) => {
        if (!inst.instanceId) return;
        try {
          const attr = await ec2.send(
            new DescribeInstanceAttributeCommand({
              InstanceId: inst.instanceId,
              Attribute: "userData",
            }),
          );
          const b64 = attr.UserData?.Value;
          if (b64) inst.userData = Buffer.from(b64, "base64").toString("utf8");
        } catch {
          // Leave userData undefined; see comment above.
        }
      });
      return out;
    },

    dbInstances: async (): Promise<DiscoveredDbInstance[]> => {
      // RDS paginates with Marker (request) / Marker (response), not NextToken.
      const dbs = await paginate(
        (m) => rds.send(new DescribeDBInstancesCommand(m ? { Marker: m } : {})),
        (o) => o.DBInstances,
        (o) => o.Marker,
      );
      return dbs.map((d) => ({
        dbInstanceIdentifier: d.DBInstanceIdentifier ?? "",
        ...(d.Engine ? { engine: d.Engine } : {}),
        ...(d.Endpoint?.Port ? { port: d.Endpoint.Port } : {}),
        publiclyAccessible: d.PubliclyAccessible ?? false,
        storageEncrypted: d.StorageEncrypted ?? false,
        subnetIds: (d.DBSubnetGroup?.Subnets ?? [])
          .map((s) => s.SubnetIdentifier ?? "")
          .filter(Boolean),
        tags: tagsToRecord(d.TagList),
      }));
    },

    functions: async (): Promise<DiscoveredFunction[]> => {
      // ListFunctions already returns each function's full configuration,
      // including Environment.Variables — so there is no need for a per-function
      // GetFunctionConfiguration call (an N+1 that also required an extra
      // permission). Lambda paginates with Marker / NextMarker.
      const fns = await paginate(
        (m) => lambda.send(new ListFunctionsCommand(m ? { Marker: m } : {})),
        (o) => o.Functions,
        (o) => o.NextMarker,
      );
      const out: DiscoveredFunction[] = [];
      for (const fn of fns) {
        if (!fn.FunctionName) continue;
        out.push({
          functionName: fn.FunctionName,
          ...(fn.Runtime ? { runtime: fn.Runtime } : {}),
          environment: (fn.Environment?.Variables ?? {}) as Record<
            string,
            string
          >,
          tags: {},
        });
      }
      // Resource policy + function URL auth (FSBP Lambda.1): per function,
      // bounded concurrency; a per-function failure leaves the fields unset.
      await mapConcurrent(out, USER_DATA_CONCURRENCY, async (f) => {
        try {
          const [resourcePolicy, urlAuthTypes] = await Promise.all([
            lambdaPolicy.resourcePolicy(f.functionName),
            lambdaPolicy.urlAuthTypes(f.functionName),
          ]);
          f.resourcePolicy = resourcePolicy;
          f.urlAuthTypes = urlAuthTypes;
        } catch {
          // leave unset
        }
      });
      return out;
    },

    secrets: async (): Promise<DiscoveredSecret[]> => {
      const list = await paginate(
        (t) => sm.send(new ListSecretsCommand(t ? { NextToken: t } : {})),
        (o) => o.SecretList,
        (o) => o.NextToken,
      );
      const out: DiscoveredSecret[] = list.map((s) => ({
        arn: s.ARN ?? "",
        name: s.Name ?? "",
        rotationEnabled: s.RotationEnabled ?? false,
        tags: tagsToRecord(s.Tags),
      }));
      // Resource policy (who may read it) — metadata only; the value is never
      // fetched and the scan role has no GetSecretValue.
      await mapConcurrent(out, USER_DATA_CONCURRENCY, async (sec) => {
        try {
          const d = await secretPolicy.details(sec.arn);
          sec.rotationEnabled = d.rotationEnabled;
          sec.resourcePolicy = d.resourcePolicy;
        } catch {
          // leave unset
        }
      });
      return out;
    },

    roles: async (): Promise<DiscoveredRole[]> => {
      const ad = await authDetails();
      return ad.roles.map((r) => ({
        roleName: r.RoleName ?? "",
        arn: r.Arn ?? "",
        trustedPrincipals: parseTrustPolicy(r.AssumeRolePolicyDocument),
        identityStatements: identityStatementsFor(
          r.RolePolicyList,
          r.AttachedManagedPolicies,
          ad.managed,
        ),
        tags: tagsToRecord(r.Tags),
      }));
    },

    users: async (): Promise<DiscoveredUser[]> => {
      const ad = await authDetails();
      return ad.users.map((u) => ({
        userName: u.UserName ?? "",
        arn: u.Arn ?? "",
        identityStatements: identityStatementsFor(
          u.UserPolicyList,
          u.AttachedManagedPolicies,
          ad.managed,
        ),
        tags: tagsToRecord(u.Tags),
      }));
    },

    // --- Phase 3 optional collectors -----------------------------------------
    capabilities: () => [...PHASE3_CAPABILITIES],
    accountSummary: () => iamAccount.accountSummary(),
    credentialReport: () => iamAccount.credentialReport(),
    cloudTrails: () => audit.cloudTrails(),
    regionSettings: () => regionSettings.regionSettings(),
    s3Buckets: () => s3.s3Buckets(),
    ebsVolumes: () => ebs.ebsVolumes(),
    ebsSnapshots: () => ebs.ebsSnapshots(),
    kmsKeys: () => kms.kmsKeys(),

    // --- Tranche B ------------------------------------------------------------
    routeTables: () => routing.routeTables(),
    natGateways: () => routing.natGateways(),
    vpcPeerings: () => routing.vpcPeerings(),
    vpcEndpoints: () => routing.vpcEndpoints(),
    networkAcls: () => routing.networkAcls(),
    launchTemplates: () => routing.launchTemplates(),
    loadBalancers: () => elbv2.loadBalancers(),
    ecsClusters: () => containersB.ecsClusters(),
    ecsTaskDefinitions: () => containersB.ecsTaskDefinitions(),
    eksClusters: () => containersB.eksClusters(),
    sqsQueues: () => messaging.sqsQueues(),
    snsTopics: () => messaging.snsTopics(),
    dynamoTables: () => data.dynamoTables(),
    ecrRepositories: () => data.ecrRepositories(),
    fileSystems: () => data.fileSystems(),
    ssmParameters: () => data.ssmParameters(),
    autoScalingGroups: () => scaling.autoScalingGroups(),
    cloudFrontDistributions: () => edge.cloudFrontDistributions(),
    restApis: () => edge.restApis(),
    dbClusters: () => rdsExtra.dbClusters(),
    dbSnapshots: () => rdsExtra.dbSnapshots(),

    // --- Managed feeds ----------------------------------------------------------
    securityHubFindings: () => securityHub.securityHubFindings(),
    accessAnalyzerFindings: () => accessAnalyzer.accessAnalyzerFindings(),
  };
}

interface AuthDetails {
  roles: RoleDetail[];
  users: UserDetail[];
  /** Managed-policy ARN -> its default-version statements. */
  managed: Map<string, PolicyStatement[]>;
}

async function fetchAuthDetails(iam: IAMClient): Promise<AuthDetails> {
  const roles: RoleDetail[] = [];
  const users: UserDetail[] = [];
  const policies: ManagedPolicyDetail[] = [];
  let marker: string | undefined;
  do {
    const res = await iam.send(
      new GetAccountAuthorizationDetailsCommand({
        // Only the principal types we model as assume-role sources/targets.
        Filter: ["Role", "User", "LocalManagedPolicy", "AWSManagedPolicy"],
        ...(marker ? { Marker: marker } : {}),
      }),
    );
    roles.push(...(res.RoleDetailList ?? []));
    users.push(...(res.UserDetailList ?? []));
    policies.push(...(res.Policies ?? []));
    marker = res.IsTruncated ? res.Marker : undefined;
  } while (marker);

  const managed = new Map<string, PolicyStatement[]>();
  for (const p of policies) {
    if (!p.Arn) continue;
    const version =
      p.PolicyVersionList?.find((v) => v.IsDefaultVersion) ??
      p.PolicyVersionList?.[0];
    managed.set(p.Arn, projectStatements(version?.Document));
  }
  return { roles, users, managed };
}

/** Inline statements + resolved managed-policy statements for one principal. */
function identityStatementsFor(
  inline: PolicyDetail[] | undefined,
  attached: AttachedPolicy[] | undefined,
  managed: Map<string, PolicyStatement[]>,
): PolicyStatement[] {
  const out: PolicyStatement[] = [];
  for (const p of inline ?? []) {
    out.push(...projectStatements(p.PolicyDocument));
  }
  for (const a of attached ?? []) {
    if (a.PolicyArn) out.push(...(managed.get(a.PolicyArn) ?? []));
  }
  return out;
}

/** Parse a policy document (URL-encoded JSON) into a generic statement list. */
function parsePolicyDoc(doc: string | undefined): unknown {
  if (!doc) return undefined;
  try {
    return JSON.parse(decodeURIComponent(doc));
  } catch {
    return undefined;
  }
}

const asArray = <T>(v: T | T[] | undefined): T[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];

/** Project an identity/resource policy document to evaluable PolicyStatements. */
function projectStatements(doc: string | undefined): PolicyStatement[] {
  const parsed = parsePolicyDoc(doc) as { Statement?: unknown } | undefined;
  const out: PolicyStatement[] = [];
  for (const raw of asArray(parsed?.Statement)) {
    const s = raw as Record<string, unknown>;
    const condition = s["Condition"];
    out.push({
      effect: s["Effect"] === "Deny" ? "Deny" : "Allow",
      ...(s["Action"] ? { actions: asArray(s["Action"] as string) } : {}),
      ...(s["NotAction"]
        ? { notActions: asArray(s["NotAction"] as string) }
        : {}),
      ...(s["Resource"] ? { resources: asArray(s["Resource"] as string) } : {}),
      ...(s["NotResource"]
        ? { notResources: asArray(s["NotResource"] as string) }
        : {}),
      ...(condition ? { conditionKeys: conditionKeysOf(condition) } : {}),
    });
  }
  return out;
}

/** Collect the condition keys (e.g. sts:ExternalId) from a Condition block. */
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

/**
 * Parse an IAM trust policy (URL-encoded JSON) into a flat list of trusted
 * principals, carrying each statement's condition keys. Read-only and
 * defensive: malformed documents yield no principals.
 */
function parseTrustPolicy(
  doc: string | undefined,
): DiscoveredRole["trustedPrincipals"] {
  const parsed = parsePolicyDoc(doc) as { Statement?: unknown } | undefined;
  const out: DiscoveredRole["trustedPrincipals"] = [];
  for (const raw of asArray(parsed?.Statement)) {
    const stmt = raw as { Principal?: unknown; Condition?: unknown };
    const principal = stmt.Principal;
    if (!principal || typeof principal !== "object") continue;
    const conditionKeys = conditionKeysOf(stmt.Condition);
    for (const [key, value] of Object.entries(
      principal as Record<string, unknown>,
    )) {
      const type =
        key === "Service"
          ? "service"
          : key === "Federated"
            ? "federated"
            : "aws";
      for (const v of asArray(value as string)) {
        if (typeof v === "string") {
          out.push({
            type,
            value: v,
            ...(conditionKeys.length ? { conditionKeys } : {}),
          });
        }
      }
    }
  }
  return out;
}
