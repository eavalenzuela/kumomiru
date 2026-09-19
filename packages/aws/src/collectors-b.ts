/**
 * Tranche B SDK collectors. Same rules as collectors.ts: metadata reads
 * only, actions declared beside the calls, not-found tolerated.
 */
import {
  EC2Client,
  DescribeRouteTablesCommand,
  DescribeNatGatewaysCommand,
  DescribeVpcPeeringConnectionsCommand,
  DescribeVpcEndpointsCommand,
  DescribeNetworkAclsCommand,
  DescribeLaunchTemplatesCommand,
  DescribeLaunchTemplateVersionsCommand,
} from "@aws-sdk/client-ec2";
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
  DescribeLoadBalancerAttributesCommand,
  DescribeTagsCommand as DescribeElbTagsCommand,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import {
  ECSClient,
  ListClustersCommand,
  DescribeClustersCommand,
  ListServicesCommand,
  DescribeServicesCommand,
  ListTaskDefinitionsCommand,
  DescribeTaskDefinitionCommand,
} from "@aws-sdk/client-ecs";
import { EKSClient, ListClustersCommand as ListEksClustersCommand, DescribeClusterCommand as DescribeEksClusterCommand } from "@aws-sdk/client-eks";
import { SQSClient, ListQueuesCommand, GetQueueAttributesCommand, ListQueueTagsCommand } from "@aws-sdk/client-sqs";
import { SNSClient, ListTopicsCommand, GetTopicAttributesCommand, ListTagsForResourceCommand as ListSnsTagsCommand } from "@aws-sdk/client-sns";
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand, DescribeContinuousBackupsCommand } from "@aws-sdk/client-dynamodb";
import { ECRClient, DescribeRepositoriesCommand, GetRepositoryPolicyCommand, GetLifecyclePolicyCommand } from "@aws-sdk/client-ecr";
import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { EFSClient, DescribeFileSystemsCommand, DescribeFileSystemPolicyCommand } from "@aws-sdk/client-efs";
import { CloudFrontClient, ListDistributionsCommand, GetDistributionConfigCommand } from "@aws-sdk/client-cloudfront";
import { APIGatewayClient, GetRestApisCommand, GetStagesCommand } from "@aws-sdk/client-api-gateway";
import { RDSClient, DescribeDBClustersCommand, DescribeDBSnapshotsCommand, DescribeDBSnapshotAttributesCommand, DescribeDBClusterSnapshotsCommand, DescribeDBClusterSnapshotAttributesCommand } from "@aws-sdk/client-rds";
import { SSMClient, DescribeParametersCommand } from "@aws-sdk/client-ssm";

import {
  projectPolicyDocument,
  type DiscoveredAutoScalingGroup,
  type DiscoveredDbCluster,
  type DiscoveredDbSnapshot,
  type DiscoveredDistribution,
  type DiscoveredEcrRepository,
  type DiscoveredEcsCluster,
  type DiscoveredEksCluster,
  type DiscoveredFileSystem,
  type DiscoveredLaunchTemplate,
  type DiscoveredLoadBalancer,
  type DiscoveredNatGateway,
  type DiscoveredNetworkAcl,
  type DiscoveredQueue,
  type DiscoveredRestApi,
  type DiscoveredRouteTable,
  type DiscoveredSsmParameter,
  type DiscoveredTaskDefinition,
  type DiscoveredTopic,
  type DiscoveredVpcEndpoint,
  type DiscoveredVpcPeering,
  type DiscoveredDynamoTable,
} from "@kumomiru/adapters";

export const TRANCHE_B_ACTIONS = [
  "ec2:DescribeRouteTables",
  "ec2:DescribeNatGateways",
  "ec2:DescribeVpcPeeringConnections",
  "ec2:DescribeVpcEndpoints",
  "ec2:DescribeNetworkAcls",
  "ec2:DescribeLaunchTemplates",
  "ec2:DescribeLaunchTemplateVersions",
  "elasticloadbalancing:DescribeLoadBalancers",
  "elasticloadbalancing:DescribeListeners",
  "elasticloadbalancing:DescribeTargetGroups",
  "elasticloadbalancing:DescribeTargetHealth",
  "elasticloadbalancing:DescribeLoadBalancerAttributes",
  "elasticloadbalancing:DescribeTags",
  "ecs:ListClusters",
  "ecs:DescribeClusters",
  "ecs:ListServices",
  "ecs:DescribeServices",
  "ecs:ListTaskDefinitions",
  "ecs:DescribeTaskDefinition",
  "eks:ListClusters",
  "eks:DescribeCluster",
  "sqs:ListQueues",
  "sqs:GetQueueAttributes",
  "sqs:ListQueueTags",
  "sns:ListTopics",
  "sns:GetTopicAttributes",
  "sns:ListTagsForResource",
  "dynamodb:ListTables",
  "dynamodb:DescribeTable",
  "dynamodb:DescribeContinuousBackups",
  "ecr:DescribeRepositories",
  "ecr:GetRepositoryPolicy",
  "ecr:GetLifecyclePolicy",
  "autoscaling:DescribeAutoScalingGroups",
  "elasticfilesystem:DescribeFileSystems",
  "elasticfilesystem:DescribeFileSystemPolicy",
  "cloudfront:ListDistributions",
  "cloudfront:GetDistributionConfig",
  "apigateway:GET",
  "rds:DescribeDBClusters",
  "rds:DescribeDBSnapshots",
  "rds:DescribeDBSnapshotAttributes",
  "rds:DescribeDBClusterSnapshots",
  "rds:DescribeDBClusterSnapshotAttributes",
  "ssm:DescribeParameters",
] as const;

type Cfg = { region: string; credentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string } };

async function optional<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    const name = (err as { name?: string })?.name ?? "";
    if (/NoSuch|NotFound|PolicyNotFound|LifecyclePolicyNotFound|ResourceNotFound|InvalidParameter|AccessDenied/.test(name)) return fallback;
    throw err;
  }
}

async function mapConcurrent<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function tags(list: Array<{ Key?: string; Value?: string; key?: string; value?: string }> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of list ?? []) {
    const k = t.Key ?? t.key;
    if (k) out[k] = t.Value ?? t.value ?? "";
  }
  return out;
}

async function paginate<O, I>(call: (token?: string) => Promise<O>, items: (o: O) => I[] | undefined, next: (o: O) => string | undefined): Promise<I[]> {
  const out: I[] = [];
  let token: string | undefined;
  do {
    const res = await call(token);
    out.push(...(items(res) ?? []));
    token = next(res);
  } while (token);
  return out;
}

// --- EC2 routing / NACL / launch templates -------------------------------------

export function routingCollector(cfg: Cfg) {
  const ec2 = new EC2Client(cfg);
  return {
    async routeTables(): Promise<DiscoveredRouteTable[]> {
      const rts = await paginate((t) => ec2.send(new DescribeRouteTablesCommand(t ? { NextToken: t } : {})), (o) => o.RouteTables, (o) => o.NextToken);
      return rts.map((rt) => ({
        routeTableId: rt.RouteTableId ?? "",
        vpcId: rt.VpcId ?? "",
        subnetIds: (rt.Associations ?? []).map((a) => a.SubnetId ?? "").filter(Boolean),
        main: (rt.Associations ?? []).some((a) => a.Main === true),
        routes: (rt.Routes ?? []).map((r) => {
          const destination = r.DestinationCidrBlock ?? r.DestinationIpv6CidrBlock ?? r.DestinationPrefixListId ?? "";
          const [targetType, targetId] = r.GatewayId?.startsWith("igw-") ? ["igw", r.GatewayId] as const
            : r.GatewayId === "local" ? ["local", undefined] as const
            : r.NatGatewayId ? ["nat", r.NatGatewayId] as const
            : r.VpcPeeringConnectionId ? ["peering", r.VpcPeeringConnectionId] as const
            : r.GatewayId?.startsWith("vpce-") ? ["vpce", r.GatewayId] as const
            : r.InstanceId ? ["instance", r.InstanceId] as const
            : ["other", r.GatewayId ?? r.TransitGatewayId ?? r.NetworkInterfaceId] as const;
          return { destination, targetType, ...(targetId ? { targetId } : {}) };
        }),
        tags: tags(rt.Tags),
      }));
    },
    async natGateways(): Promise<DiscoveredNatGateway[]> {
      const nats = await paginate((t) => ec2.send(new DescribeNatGatewaysCommand(t ? { NextToken: t } : {})), (o) => o.NatGateways, (o) => o.NextToken);
      return nats.filter((n) => n.State !== "deleted").map((n) => ({
        natGatewayId: n.NatGatewayId ?? "",
        ...(n.VpcId ? { vpcId: n.VpcId } : {}),
        ...(n.SubnetId ? { subnetId: n.SubnetId } : {}),
        tags: tags(n.Tags),
      }));
    },
    async vpcPeerings(): Promise<DiscoveredVpcPeering[]> {
      const ps = await paginate((t) => ec2.send(new DescribeVpcPeeringConnectionsCommand(t ? { NextToken: t } : {})), (o) => o.VpcPeeringConnections, (o) => o.NextToken);
      return ps.map((p) => ({
        peeringId: p.VpcPeeringConnectionId ?? "",
        ...(p.RequesterVpcInfo?.VpcId ? { requesterVpcId: p.RequesterVpcInfo.VpcId } : {}),
        ...(p.RequesterVpcInfo?.OwnerId ? { requesterAccount: p.RequesterVpcInfo.OwnerId } : {}),
        ...(p.AccepterVpcInfo?.VpcId ? { accepterVpcId: p.AccepterVpcInfo.VpcId } : {}),
        ...(p.AccepterVpcInfo?.OwnerId ? { accepterAccount: p.AccepterVpcInfo.OwnerId } : {}),
        ...(p.Status?.Code ? { status: p.Status.Code } : {}),
        tags: tags(p.Tags),
      }));
    },
    async vpcEndpoints(): Promise<DiscoveredVpcEndpoint[]> {
      const eps = await paginate((t) => ec2.send(new DescribeVpcEndpointsCommand(t ? { NextToken: t } : {})), (o) => o.VpcEndpoints, (o) => o.NextToken);
      return eps.map((e) => ({
        endpointId: e.VpcEndpointId ?? "",
        ...(e.VpcId ? { vpcId: e.VpcId } : {}),
        serviceName: e.ServiceName ?? "",
        type: e.VpcEndpointType ?? "Interface",
        tags: tags(e.Tags),
      }));
    },
    async networkAcls(): Promise<DiscoveredNetworkAcl[]> {
      const acls = await paginate((t) => ec2.send(new DescribeNetworkAclsCommand(t ? { NextToken: t } : {})), (o) => o.NetworkAcls, (o) => o.NextToken);
      return acls.map((a) => ({
        aclId: a.NetworkAclId ?? "",
        ...(a.VpcId ? { vpcId: a.VpcId } : {}),
        subnetIds: (a.Associations ?? []).map((x) => x.SubnetId ?? "").filter(Boolean),
        isDefault: a.IsDefault ?? false,
        entries: (a.Entries ?? []).map((e) => ({
          ruleNumber: e.RuleNumber ?? 0,
          egress: e.Egress ?? false,
          protocol: e.Protocol ?? "-1",
          ...(e.PortRange?.From !== undefined ? { fromPort: e.PortRange.From } : {}),
          ...(e.PortRange?.To !== undefined ? { toPort: e.PortRange.To } : {}),
          ...(e.CidrBlock ?? e.Ipv6CidrBlock ? { cidr: e.CidrBlock ?? e.Ipv6CidrBlock } : {}),
          action: e.RuleAction === "deny" ? "deny" : "allow",
        })),
        tags: tags(a.Tags),
      }));
    },
    async launchTemplates(): Promise<DiscoveredLaunchTemplate[]> {
      const lts = await paginate((t) => ec2.send(new DescribeLaunchTemplatesCommand(t ? { NextToken: t } : {})), (o) => o.LaunchTemplates, (o) => o.NextToken);
      return mapConcurrent(lts, 6, async (lt) => {
        const id = lt.LaunchTemplateId ?? "";
        const v = await optional(() => ec2.send(new DescribeLaunchTemplateVersionsCommand({ LaunchTemplateId: id, Versions: ["$Default"] })), undefined);
        const data = v?.LaunchTemplateVersions?.[0]?.LaunchTemplateData;
        return {
          launchTemplateId: id,
          name: lt.LaunchTemplateName ?? id,
          ...(data?.UserData ? { userData: Buffer.from(data.UserData, "base64").toString("utf8") } : {}),
          ...(data?.MetadataOptions?.HttpTokens ? { imdsv2Required: data.MetadataOptions.HttpTokens === "required" } : {}),
          tags: tags(lt.Tags),
        };
      });
    },
  };
}

// --- ELBv2 -------------------------------------------------------------------------

export function elbCollector(cfg: Cfg) {
  const elb = new ElasticLoadBalancingV2Client(cfg);
  return {
    async loadBalancers(): Promise<DiscoveredLoadBalancer[]> {
      const lbs = await paginate((m) => elb.send(new DescribeLoadBalancersCommand(m ? { Marker: m } : {})), (o) => o.LoadBalancers, (o) => o.NextMarker);
      const tgs = await paginate((m) => elb.send(new DescribeTargetGroupsCommand(m ? { Marker: m } : {})), (o) => o.TargetGroups, (o) => o.NextMarker);
      const tgByLb = new Map<string, typeof tgs>();
      for (const tg of tgs) for (const lbArn of tg.LoadBalancerArns ?? []) tgByLb.set(lbArn, [...(tgByLb.get(lbArn) ?? []), tg]);
      return mapConcurrent(lbs, 4, async (lb) => {
        const arn = lb.LoadBalancerArn ?? "";
        const [listeners, attrs, tagRes, targets] = await Promise.all([
          paginate((m) => elb.send(new DescribeListenersCommand({ LoadBalancerArn: arn, ...(m ? { Marker: m } : {}) })), (o) => o.Listeners, (o) => o.NextMarker),
          optional(() => elb.send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: arn })), undefined),
          optional(() => elb.send(new DescribeElbTagsCommand({ ResourceArns: [arn] })), undefined),
          mapConcurrent(tgByLb.get(arn) ?? [], 4, async (tg) => {
            const h = await optional(() => elb.send(new DescribeTargetHealthCommand({ TargetGroupArn: tg.TargetGroupArn })), undefined);
            return (h?.TargetHealthDescriptions ?? []).map((d) => ({
              targetGroupArn: tg.TargetGroupArn ?? "",
              targetType: tg.TargetType ?? "instance",
              id: d.Target?.Id ?? "",
              ...(d.Target?.Port !== undefined ? { port: d.Target.Port } : {}),
            }));
          }),
        ]);
        const accessLogs = attrs?.Attributes?.find((a) => a.Key === "access_logs.s3.enabled")?.Value;
        return {
          arn,
          name: lb.LoadBalancerName ?? arn,
          type: (lb.Type ?? "application") as DiscoveredLoadBalancer["type"],
          scheme: lb.Scheme === "internal" ? "internal" : "internet-facing",
          ...(lb.VpcId ? { vpcId: lb.VpcId } : {}),
          subnetIds: (lb.AvailabilityZones ?? []).map((z) => z.SubnetId ?? "").filter(Boolean),
          securityGroupIds: lb.SecurityGroups ?? [],
          ...(lb.DNSName ? { dnsName: lb.DNSName } : {}),
          ...(accessLogs !== undefined ? { accessLogsEnabled: accessLogs === "true" } : {}),
          listeners: listeners.map((l) => ({
            port: l.Port ?? 0,
            protocol: l.Protocol ?? "",
            redirectsToHttps: (l.DefaultActions ?? []).some((a) => a.Type === "redirect" && a.RedirectConfig?.Protocol === "HTTPS"),
          })),
          targets: targets.flat(),
          tags: tags(tagRes?.TagDescriptions?.[0]?.Tags),
        };
      });
    },
  };
}

// --- ECS / EKS ------------------------------------------------------------------------

export function containerCollector(cfg: Cfg) {
  const ecs = new ECSClient(cfg);
  const eks = new EKSClient(cfg);
  return {
    async ecsClusters(): Promise<DiscoveredEcsCluster[]> {
      const arns = await paginate((t) => ecs.send(new ListClustersCommand(t ? { nextToken: t } : {})), (o) => o.clusterArns, (o) => o.nextToken);
      if (arns.length === 0) return [];
      const described = (await ecs.send(new DescribeClustersCommand({ clusters: arns, include: ["TAGS"] }))).clusters ?? [];
      return mapConcurrent(described, 4, async (c) => {
        const arn = c.clusterArn ?? "";
        const svcArns = await paginate((t) => ecs.send(new ListServicesCommand({ cluster: arn, ...(t ? { nextToken: t } : {}) })), (o) => o.serviceArns, (o) => o.nextToken);
        const services: DiscoveredEcsCluster["services"] = [];
        for (let i = 0; i < svcArns.length; i += 10) {
          const chunk = svcArns.slice(i, i + 10);
          const res = await ecs.send(new DescribeServicesCommand({ cluster: arn, services: chunk }));
          for (const s of res.services ?? []) {
            const net = s.networkConfiguration?.awsvpcConfiguration;
            services.push({
              arn: s.serviceArn ?? "",
              name: s.serviceName ?? "",
              ...(s.taskDefinition ? { taskDefinitionArn: s.taskDefinition } : {}),
              ...(s.launchType ? { launchType: s.launchType } : {}),
              assignPublicIp: net?.assignPublicIp === "ENABLED",
              subnetIds: net?.subnets ?? [],
              securityGroupIds: net?.securityGroups ?? [],
            });
          }
        }
        return { arn, name: c.clusterName ?? arn, services, tags: tags(c.tags) };
      });
    },
    async ecsTaskDefinitions(): Promise<DiscoveredTaskDefinition[]> {
      // Only the latest ACTIVE revision per family; older revisions are noise.
      const arns = await paginate((t) => ecs.send(new ListTaskDefinitionsCommand({ status: "ACTIVE", sort: "DESC", ...(t ? { nextToken: t } : {}) })), (o) => o.taskDefinitionArns, (o) => o.nextToken);
      const latest = new Map<string, string>();
      for (const a of arns) {
        const family = a.split("/").pop()?.split(":")[0] ?? a;
        if (!latest.has(family)) latest.set(family, a);
      }
      return mapConcurrent([...latest.values()], 6, async (arn) => {
        const res = await ecs.send(new DescribeTaskDefinitionCommand({ taskDefinition: arn, include: ["TAGS"] }));
        const td = res.taskDefinition;
        return {
          arn: td?.taskDefinitionArn ?? arn,
          family: td?.family ?? arn,
          containers: (td?.containerDefinitions ?? []).map((c) => ({
            name: c.name ?? "",
            ...(c.image ? { image: c.image } : {}),
            environment: Object.fromEntries((c.environment ?? []).map((e) => [e.name ?? "", e.value ?? ""])),
          })),
          tags: tags(res.tags),
        };
      });
    },
    async eksClusters(): Promise<DiscoveredEksCluster[]> {
      const names = await paginate((t) => eks.send(new ListEksClustersCommand(t ? { nextToken: t } : {})), (o) => o.clusters, (o) => o.nextToken);
      return mapConcurrent(names, 4, async (name) => {
        const c = (await eks.send(new DescribeEksClusterCommand({ name }))).cluster;
        const vpc = c?.resourcesVpcConfig;
        return {
          arn: c?.arn ?? name,
          name,
          ...(c?.version ? { version: c.version } : {}),
          ...(vpc?.vpcId ? { vpcId: vpc.vpcId } : {}),
          subnetIds: vpc?.subnetIds ?? [],
          securityGroupIds: [...(vpc?.securityGroupIds ?? []), ...(vpc?.clusterSecurityGroupId ? [vpc.clusterSecurityGroupId] : [])],
          endpointPublicAccess: vpc?.endpointPublicAccess ?? false,
          endpointPrivateAccess: vpc?.endpointPrivateAccess ?? false,
          publicAccessCidrs: vpc?.publicAccessCidrs ?? [],
          loggingEnabled: (c?.logging?.clusterLogging ?? []).some((l) => l.enabled === true),
          tags: c?.tags ?? {},
        };
      });
    },
  };
}

// --- SQS / SNS ------------------------------------------------------------------------

export function messagingCollector(cfg: Cfg) {
  const sqs = new SQSClient(cfg);
  const sns = new SNSClient(cfg);
  return {
    async sqsQueues(): Promise<DiscoveredQueue[]> {
      const urls = await paginate((t) => sqs.send(new ListQueuesCommand(t ? { NextToken: t } : {})), (o) => o.QueueUrls, (o) => o.NextToken);
      return mapConcurrent(urls, 6, async (url) => {
        const [attrs, tagRes] = await Promise.all([
          sqs.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ["QueueArn", "Policy", "KmsMasterKeyId", "SqsManagedSseEnabled"] })),
          optional(() => sqs.send(new ListQueueTagsCommand({ QueueUrl: url })), undefined),
        ]);
        const a = attrs.Attributes ?? {};
        return {
          arn: a["QueueArn"] ?? url,
          name: url.split("/").pop() ?? url,
          kmsEncrypted: Boolean(a["KmsMasterKeyId"]) || a["SqsManagedSseEnabled"] === "true",
          policyStatements: a["Policy"] ? projectPolicyDocument(a["Policy"]) : [],
          tags: tagRes?.Tags ?? {},
        };
      });
    },
    async snsTopics(): Promise<DiscoveredTopic[]> {
      const topics = await paginate((t) => sns.send(new ListTopicsCommand(t ? { NextToken: t } : {})), (o) => o.Topics, (o) => o.NextToken);
      return mapConcurrent(topics, 6, async (t) => {
        const arn = t.TopicArn ?? "";
        const [attrs, tagRes] = await Promise.all([
          sns.send(new GetTopicAttributesCommand({ TopicArn: arn })),
          optional(() => sns.send(new ListSnsTagsCommand({ ResourceArn: arn })), undefined),
        ]);
        const a = attrs.Attributes ?? {};
        return {
          arn,
          name: arn.split(":").pop() ?? arn,
          kmsEncrypted: Boolean(a["KmsMasterKeyId"]),
          policyStatements: a["Policy"] ? projectPolicyDocument(a["Policy"]) : [],
          tags: tags(tagRes?.Tags),
        };
      });
    },
  };
}

// --- DynamoDB / ECR / EFS / SSM ---------------------------------------------------------

export function dataCollector(cfg: Cfg) {
  const ddb = new DynamoDBClient(cfg);
  const ecr = new ECRClient(cfg);
  const efs = new EFSClient(cfg);
  const ssm = new SSMClient(cfg);
  return {
    async dynamoTables(): Promise<DiscoveredDynamoTable[]> {
      const names = await paginate((t) => ddb.send(new ListTablesCommand(t ? { ExclusiveStartTableName: t } : {})), (o) => o.TableNames, (o) => o.LastEvaluatedTableName);
      return mapConcurrent(names, 6, async (name) => {
        const [desc, backups] = await Promise.all([
          ddb.send(new DescribeTableCommand({ TableName: name })),
          optional(() => ddb.send(new DescribeContinuousBackupsCommand({ TableName: name })), undefined),
        ]);
        const t = desc.Table;
        return {
          arn: t?.TableArn ?? name,
          name,
          ...(backups ? { pitrEnabled: backups.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus === "ENABLED" } : {}),
          ...(t?.DeletionProtectionEnabled !== undefined ? { deletionProtection: t.DeletionProtectionEnabled } : {}),
          ...(t?.SSEDescription?.KMSMasterKeyArn ? { kmsKeyArn: t.SSEDescription.KMSMasterKeyArn } : {}),
          tags: {},
        };
      });
    },
    async ecrRepositories(): Promise<DiscoveredEcrRepository[]> {
      const repos = await paginate((t) => ecr.send(new DescribeRepositoriesCommand(t ? { nextToken: t } : {})), (o) => o.repositories, (o) => o.nextToken);
      return mapConcurrent(repos, 6, async (r) => {
        const name = r.repositoryName ?? "";
        const [policy, lifecycle] = await Promise.all([
          optional(async () => (await ecr.send(new GetRepositoryPolicyCommand({ repositoryName: name }))).policyText, undefined),
          optional(async () => (await ecr.send(new GetLifecyclePolicyCommand({ repositoryName: name }))).lifecyclePolicyText, undefined),
        ]);
        return {
          arn: r.repositoryArn ?? name,
          name,
          scanOnPush: r.imageScanningConfiguration?.scanOnPush ?? false,
          tagImmutability: r.imageTagMutability === "IMMUTABLE",
          lifecyclePolicy: Boolean(lifecycle),
          policyStatements: policy ? projectPolicyDocument(policy) : [],
          tags: {},
        };
      });
    },
    async fileSystems(): Promise<DiscoveredFileSystem[]> {
      const fss = await paginate((m) => efs.send(new DescribeFileSystemsCommand(m ? { Marker: m } : {})), (o) => o.FileSystems, (o) => o.NextMarker);
      return mapConcurrent(fss, 6, async (fs) => {
        const id = fs.FileSystemId ?? "";
        const policy = await optional(async () => (await efs.send(new DescribeFileSystemPolicyCommand({ FileSystemId: id }))).Policy, undefined);
        return {
          arn: fs.FileSystemArn ?? id,
          fileSystemId: id,
          ...(fs.Name ? { name: fs.Name } : {}),
          encrypted: fs.Encrypted ?? false,
          ...(fs.KmsKeyId ? { kmsKeyId: fs.KmsKeyId } : {}),
          policyStatements: policy ? projectPolicyDocument(policy) : [],
          tags: tags(fs.Tags),
        };
      });
    },
    /** Metadata only: name and type. Values are never read (no ssm:GetParameter*). */
    async ssmParameters(): Promise<DiscoveredSsmParameter[]> {
      const params = await paginate((t) => ssm.send(new DescribeParametersCommand(t ? { NextToken: t } : {})), (o) => o.Parameters, (o) => o.NextToken);
      return params.map((p) => ({ arn: p.ARN ?? p.Name ?? "", name: p.Name ?? "", type: p.Type ?? "String" }));
    },
  };
}

// --- ASG ----------------------------------------------------------------------------

export function scalingCollector(cfg: Cfg) {
  const asg = new AutoScalingClient(cfg);
  return {
    async autoScalingGroups(): Promise<DiscoveredAutoScalingGroup[]> {
      const groups = await paginate((t) => asg.send(new DescribeAutoScalingGroupsCommand(t ? { NextToken: t } : {})), (o) => o.AutoScalingGroups, (o) => o.NextToken);
      return groups.map((g) => ({
        arn: g.AutoScalingGroupARN ?? g.AutoScalingGroupName ?? "",
        name: g.AutoScalingGroupName ?? "",
        ...(g.LaunchTemplate?.LaunchTemplateId ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification?.LaunchTemplateId
          ? { launchTemplateId: (g.LaunchTemplate?.LaunchTemplateId ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification?.LaunchTemplateId)! }
          : {}),
        ...(g.LaunchConfigurationName ? { launchConfigurationName: g.LaunchConfigurationName } : {}),
        instanceIds: (g.Instances ?? []).map((i) => i.InstanceId ?? "").filter(Boolean),
        subnetIds: (g.VPCZoneIdentifier ?? "").split(",").filter(Boolean),
        tags: tags(g.Tags),
      }));
    },
  };
}

// --- CloudFront / API Gateway -----------------------------------------------------------

export function edgeCollector(cfg: Cfg) {
  const cf = new CloudFrontClient({ ...cfg, region: "us-east-1" });
  const apigw = new APIGatewayClient(cfg);
  return {
    async cloudFrontDistributions(): Promise<DiscoveredDistribution[]> {
      const items = await paginate((m) => cf.send(new ListDistributionsCommand(m ? { Marker: m } : {})), (o) => o.DistributionList?.Items, (o) => (o.DistributionList?.IsTruncated ? o.DistributionList.NextMarker : undefined));
      return mapConcurrent(items, 4, async (d) => {
        const id = d.Id ?? "";
        const cfgRes = await optional(() => cf.send(new GetDistributionConfigCommand({ Id: id })), undefined);
        const c = cfgRes?.DistributionConfig;
        return {
          arn: d.ARN ?? `arn:aws:cloudfront::${id}`,
          id,
          domainName: d.DomainName ?? id,
          enabled: c?.Enabled ?? d.Enabled ?? false,
          viewerProtocolPolicy: c?.DefaultCacheBehavior?.ViewerProtocolPolicy ?? d.DefaultCacheBehavior?.ViewerProtocolPolicy ?? "allow-all",
          loggingEnabled: c?.Logging?.Enabled ?? false,
          origins: (c?.Origins?.Items ?? d.Origins?.Items ?? []).map((o) => ({
            id: o.Id ?? "",
            domainName: o.DomainName ?? "",
            type: o.S3OriginConfig || /\.s3[.-]/.test(o.DomainName ?? "") ? "s3" : "custom",
          })),
          tags: {},
        };
      });
    },
    async restApis(): Promise<DiscoveredRestApi[]> {
      const apis = await paginate((p) => apigw.send(new GetRestApisCommand(p ? { position: p } : {})), (o) => o.items, (o) => o.position);
      return mapConcurrent(apis, 4, async (a) => {
        const id = a.id ?? "";
        const stages = await optional(() => apigw.send(new GetStagesCommand({ restApiId: id })), undefined);
        return {
          id,
          arn: `arn:aws:apigateway:${cfg.region}::/restapis/${id}`,
          name: a.name ?? id,
          stages: (stages?.item ?? []).map((s) => ({
            name: s.stageName ?? "",
            loggingEnabled: Object.values(s.methodSettings ?? {}).some((m) => Boolean(m.loggingLevel && m.loggingLevel !== "OFF")),
            tracingEnabled: s.tracingEnabled ?? false,
          })),
          tags: a.tags ?? {},
        };
      });
    },
  };
}

// --- RDS clusters / snapshots ------------------------------------------------------------

export function rdsExtraCollector(cfg: Cfg) {
  const rds = new RDSClient(cfg);
  return {
    async dbClusters(): Promise<DiscoveredDbCluster[]> {
      const cs = await paginate((m) => rds.send(new DescribeDBClustersCommand(m ? { Marker: m } : {})), (o) => o.DBClusters, (o) => o.Marker);
      return cs.map((c) => ({
        arn: c.DBClusterArn ?? c.DBClusterIdentifier ?? "",
        identifier: c.DBClusterIdentifier ?? "",
        ...(c.Engine ? { engine: c.Engine } : {}),
        ...(c.StorageEncrypted !== undefined ? { storageEncrypted: c.StorageEncrypted } : {}),
        memberInstanceIdentifiers: (c.DBClusterMembers ?? []).map((m) => m.DBInstanceIdentifier ?? "").filter(Boolean),
        tags: tags(c.TagList),
      }));
    },
    async dbSnapshots(): Promise<DiscoveredDbSnapshot[]> {
      const [inst, clus] = await Promise.all([
        paginate((m) => rds.send(new DescribeDBSnapshotsCommand({ SnapshotType: "manual", ...(m ? { Marker: m } : {}) })), (o) => o.DBSnapshots, (o) => o.Marker),
        paginate((m) => rds.send(new DescribeDBClusterSnapshotsCommand({ SnapshotType: "manual", ...(m ? { Marker: m } : {}) })), (o) => o.DBClusterSnapshots, (o) => o.Marker),
      ]);
      const a = await mapConcurrent(inst, 6, async (s) => {
        const attr = await optional(() => rds.send(new DescribeDBSnapshotAttributesCommand({ DBSnapshotIdentifier: s.DBSnapshotIdentifier })), undefined);
        const pub = (attr?.DBSnapshotAttributesResult?.DBSnapshotAttributes ?? []).some((x) => x.AttributeName === "restore" && (x.AttributeValues ?? []).includes("all"));
        return { arn: s.DBSnapshotArn ?? "", identifier: s.DBSnapshotIdentifier ?? "", kind: "instance" as const, encrypted: s.Encrypted ?? false, public: pub, tags: tags(s.TagList) };
      });
      const b = await mapConcurrent(clus, 6, async (s) => {
        const attr = await optional(() => rds.send(new DescribeDBClusterSnapshotAttributesCommand({ DBClusterSnapshotIdentifier: s.DBClusterSnapshotIdentifier })), undefined);
        const pub = (attr?.DBClusterSnapshotAttributesResult?.DBClusterSnapshotAttributes ?? []).some((x) => x.AttributeName === "restore" && (x.AttributeValues ?? []).includes("all"));
        return { arn: s.DBClusterSnapshotArn ?? "", identifier: s.DBClusterSnapshotIdentifier ?? "", kind: "cluster" as const, encrypted: s.StorageEncrypted ?? false, public: pub, tags: tags(s.TagList) };
      });
      return [...a, ...b];
    },
  };
}
