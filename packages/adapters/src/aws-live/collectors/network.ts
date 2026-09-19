import { ingressAttribute } from "../../common/ingress.js";
import { type CollectContext, isInternetFacing, nameFromTags, portLabel } from "../collect.js";

/** Internet-facing ingress per SG, consumed by the compute collector. */
export type InternetIngress = Map<string, { ports: string; cidr: string }>;

/** VPCs, subnets, internet gateways, security groups. */
export async function collectNetwork(ctx: CollectContext): Promise<InternetIngress> {
  const { client, account, region, arn, regionId, nodes, edges } = ctx;

  for (const vpc of await client.vpcs()) {
    const id = arn.vpc(account, region, vpc.vpcId);
    ctx.index.vpc.set(vpc.vpcId, id);
    nodes.push({
      id,
      type: "aws::ec2::vpc",
      name: nameFromTags(vpc.tags, vpc.vpcId),
      account,
      region,
      parent: regionId,
      tags: vpc.tags,
      attributes: {
        ...(vpc.cidrBlock ? { cidrBlock: vpc.cidrBlock } : {}),
        ...(vpc.flowLogsEnabled !== undefined ? { flowLogsEnabled: vpc.flowLogsEnabled } : {}),
      },
    });
  }

  for (const subnet of await client.subnets()) {
    const id = arn.subnet(account, region, subnet.subnetId);
    ctx.index.subnet.set(subnet.subnetId, id);
    nodes.push({
      id,
      type: "aws::ec2::subnet",
      name: nameFromTags(subnet.tags, subnet.subnetId),
      account,
      region,
      parent: ctx.index.vpc.get(subnet.vpcId) ?? regionId,
      tags: subnet.tags,
      attributes: {
        ...(subnet.cidrBlock ? { cidrBlock: subnet.cidrBlock } : {}),
        ...(subnet.availabilityZone ? { availabilityZone: subnet.availabilityZone } : {}),
        mapPublicIpOnLaunch: subnet.mapPublicIpOnLaunch ?? false,
      },
    });
  }

  for (const igw of await client.internetGateways()) {
    const id = arn.igw(account, region, igw.internetGatewayId);
    ctx.index.igw.set(igw.internetGatewayId, id);
    const parent = igw.attachedVpcId ? (ctx.index.vpc.get(igw.attachedVpcId) ?? regionId) : regionId;
    nodes.push({
      id,
      type: "aws::ec2::internet-gateway",
      name: nameFromTags(igw.tags, igw.internetGatewayId),
      account,
      region,
      parent,
      tags: igw.tags,
      attributes: {},
    });
    if (igw.attachedVpcId && ctx.index.vpc.has(igw.attachedVpcId)) {
      edges.push({
        id: `e-igw-${igw.internetGatewayId}`,
        source: id,
        target: ctx.index.vpc.get(igw.attachedVpcId)!,
        relationship: "attached-to",
        lens: "network",
        attributes: {},
      });
    }
  }

  const internet: InternetIngress = new Map();
  for (const sg of await client.securityGroups()) {
    const id = arn.sg(account, region, sg.groupId);
    ctx.index.sg.set(sg.groupId, id);
    nodes.push({
      id,
      type: "aws::ec2::security-group",
      name: sg.groupName ?? sg.groupId,
      account,
      region,
      parent: sg.vpcId ? (ctx.index.vpc.get(sg.vpcId) ?? regionId) : regionId,
      tags: sg.tags,
      // The rule engine evaluates exposure from these; the shape is shared
      // with the Terraform adapter (common/ingress.ts).
      attributes: { ingress: ingressAttribute(sg.ingress) },
    });
    for (const rule of sg.ingress) {
      const ports = portLabel(rule.fromPort, rule.toPort);
      if (isInternetFacing(rule.cidrs)) {
        const cidr = rule.cidrs.find((c) => c === "0.0.0.0/0" || c === "::/0") ?? "0.0.0.0/0";
        internet.set(sg.groupId, { ports, cidr });
      }
      if (rule.sourceGroupIds && rule.sourceGroupIds.length > 0) {
        ctx.df.ingress.push({ groupId: sg.groupId, sourceGroupIds: rule.sourceGroupIds, ports });
      }
    }
  }
  ctx.index.internet = internet;
  return internet;
}
