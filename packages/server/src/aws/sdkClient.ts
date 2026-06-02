import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import {
  EC2Client,
  DescribeVpcsCommand,
  DescribeSubnetsCommand,
  DescribeInternetGatewaysCommand,
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
} from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import {
  LambdaClient,
  ListFunctionsCommand,
  GetFunctionConfigurationCommand,
} from "@aws-sdk/client-lambda";
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

/**
 * The real, SDK-backed read-only DiscoveryClient. This is the ONLY place the
 * AWS SDK is used. Every command here is read-only (Describe/List/Get); there is
 * no mutating call, by construction. The client is built from borrowed
 * credentials inside the credential broker's `use` scope and is discarded with
 * them.
 */
function tagsToRecord(
  tags: Array<{ Key?: string; Value?: string }> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tags ?? []) {
    if (t.Key) out[t.Key] = t.Value ?? "";
  }
  return out;
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

  return {
    region: () => region,

    accountId: async () => {
      const res = await sts.send(new GetCallerIdentityCommand({}));
      return res.Account ?? "unknown";
    },

    vpcs: async (): Promise<DiscoveredVpc[]> => {
      const res = await ec2.send(new DescribeVpcsCommand({}));
      return (res.Vpcs ?? []).map((v) => ({
        vpcId: v.VpcId ?? "",
        ...(v.CidrBlock ? { cidrBlock: v.CidrBlock } : {}),
        tags: tagsToRecord(v.Tags),
      }));
    },

    subnets: async (): Promise<DiscoveredSubnet[]> => {
      const res = await ec2.send(new DescribeSubnetsCommand({}));
      return (res.Subnets ?? []).map((s) => ({
        subnetId: s.SubnetId ?? "",
        vpcId: s.VpcId ?? "",
        ...(s.CidrBlock ? { cidrBlock: s.CidrBlock } : {}),
        ...(s.AvailabilityZone ? { availabilityZone: s.AvailabilityZone } : {}),
        mapPublicIpOnLaunch: s.MapPublicIpOnLaunch ?? false,
        tags: tagsToRecord(s.Tags),
      }));
    },

    internetGateways: async (): Promise<DiscoveredInternetGateway[]> => {
      const res = await ec2.send(new DescribeInternetGatewaysCommand({}));
      return (res.InternetGateways ?? []).map((g) => ({
        internetGatewayId: g.InternetGatewayId ?? "",
        ...(g.Attachments?.[0]?.VpcId
          ? { attachedVpcId: g.Attachments[0].VpcId }
          : {}),
        tags: tagsToRecord(g.Tags),
      }));
    },

    securityGroups: async (): Promise<DiscoveredSecurityGroup[]> => {
      const res = await ec2.send(new DescribeSecurityGroupsCommand({}));
      return (res.SecurityGroups ?? []).map((sg) => ({
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
      const res = await ec2.send(new DescribeInstancesCommand({}));
      const out: DiscoveredInstance[] = [];
      for (const r of res.Reservations ?? []) {
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
            // Note: user-data requires a separate DescribeInstanceAttribute
            // call; omitted here to keep the permission surface minimal. The
            // sanitization path is exercised when present.
            tags: tagsToRecord(i.Tags),
          });
        }
      }
      return out;
    },

    dbInstances: async (): Promise<DiscoveredDbInstance[]> => {
      const res = await rds.send(new DescribeDBInstancesCommand({}));
      return (res.DBInstances ?? []).map((d) => ({
        dbInstanceIdentifier: d.DBInstanceIdentifier ?? "",
        ...(d.Engine ? { engine: d.Engine } : {}),
        ...(d.Endpoint?.Port ? { port: d.Endpoint.Port } : {}),
        publiclyAccessible: d.PubliclyAccessible ?? false,
        subnetIds: (d.DBSubnetGroup?.Subnets ?? [])
          .map((s) => s.SubnetIdentifier ?? "")
          .filter(Boolean),
        tags: tagsToRecord(d.TagList),
      }));
    },

    functions: async (): Promise<DiscoveredFunction[]> => {
      const list = await lambda.send(new ListFunctionsCommand({}));
      const out: DiscoveredFunction[] = [];
      for (const fn of list.Functions ?? []) {
        if (!fn.FunctionName) continue;
        // Environment requires GetFunctionConfiguration; fetch per function.
        const cfgRes = await lambda.send(
          new GetFunctionConfigurationCommand({ FunctionName: fn.FunctionName }),
        );
        out.push({
          functionName: fn.FunctionName,
          ...(fn.Runtime ? { runtime: fn.Runtime } : {}),
          environment: (cfgRes.Environment?.Variables ?? {}) as Record<
            string,
            string
          >,
          tags: {},
        });
      }
      return out;
    },

    secrets: async (): Promise<DiscoveredSecret[]> => {
      const res = await sm.send(new ListSecretsCommand({}));
      return (res.SecretList ?? []).map((s) => ({
        arn: s.ARN ?? "",
        name: s.Name ?? "",
        tags: tagsToRecord(s.Tags),
      }));
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
