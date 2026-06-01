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
  ListRolesCommand,
  type Role as IamRole,
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
      const res = await iam.send(new ListRolesCommand({}));
      return (res.Roles ?? []).map((r: IamRole) => ({
        roleName: r.RoleName ?? "",
        arn: r.Arn ?? "",
        trustedPrincipals: parseTrustPolicy(r.AssumeRolePolicyDocument),
        tags: {},
      }));
    },
  };
}

/**
 * Parse an IAM trust policy (URL-encoded JSON) into a flat list of trusted
 * principals. Read-only and defensive: malformed documents yield no principals.
 */
function parseTrustPolicy(
  doc: string | undefined,
): DiscoveredRole["trustedPrincipals"] {
  if (!doc) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeURIComponent(doc));
  } catch {
    return [];
  }
  const out: DiscoveredRole["trustedPrincipals"] = [];
  const statements = (parsed as { Statement?: unknown }).Statement;
  const list = Array.isArray(statements) ? statements : [statements];
  for (const stmt of list) {
    const principal = (stmt as { Principal?: unknown })?.Principal;
    if (!principal || typeof principal !== "object") continue;
    for (const [key, value] of Object.entries(
      principal as Record<string, unknown>,
    )) {
      const type =
        key === "Service" ? "service" : key === "Federated" ? "federated" : "aws";
      const values = Array.isArray(value) ? value : [value];
      for (const v of values) {
        if (typeof v === "string") out.push({ type, value: v });
      }
    }
  }
  return out;
}
