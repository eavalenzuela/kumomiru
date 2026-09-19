import { type CollectContext, nameFromTags } from "../collect.js";

/**
 * Route tables, NAT gateways, VPC peering, VPC endpoints, network ACLs —
 * the rest of the network lens. A subnet whose route table sends
 * 0.0.0.0/0 (or ::/0) to an internet gateway is marked `public: true`.
 */
export async function collectRouting(ctx: CollectContext): Promise<void> {
  const { client, account, region, arn, regionId, nodes, edges } = ctx;

  for (const nat of (await client.natGateways?.()) ?? []) {
    const id = arn.nat(account, region, nat.natGatewayId);
    ctx.index.nat.set(nat.natGatewayId, id);
    nodes.push({
      id,
      type: "aws::ec2::nat-gateway",
      name: nameFromTags(nat.tags, nat.natGatewayId),
      account,
      region,
      parent: (nat.subnetId && ctx.index.subnet.get(nat.subnetId)) || (nat.vpcId && ctx.index.vpc.get(nat.vpcId)) || regionId,
      tags: nat.tags,
      attributes: {},
    });
  }

  const publicSubnets = new Set<string>();
  for (const rt of (await client.routeTables?.()) ?? []) {
    const id = arn.routeTable(account, region, rt.routeTableId);
    const igwDefault = rt.routes.find((r) => r.targetType === "igw" && (r.destination === "0.0.0.0/0" || r.destination === "::/0"));
    nodes.push({
      id,
      type: "aws::ec2::route-table",
      name: nameFromTags(rt.tags, rt.routeTableId),
      account,
      region,
      parent: ctx.index.vpc.get(rt.vpcId) ?? regionId,
      tags: rt.tags,
      attributes: {
        main: rt.main,
        routes: rt.routes.map((r) => ({ destination: r.destination, targetType: r.targetType, ...(r.targetId ? { targetId: r.targetId } : {}) })),
        internetRoute: Boolean(igwDefault),
      },
    });
    for (const r of rt.routes) {
      const target =
        r.targetType === "igw" && r.targetId ? ctx.index.igw.get(r.targetId)
        : r.targetType === "nat" && r.targetId ? ctx.index.nat.get(r.targetId)
        : undefined;
      if (target) {
        edges.push({
          id: `e-route-${rt.routeTableId}-${r.targetId}`,
          source: id,
          target,
          relationship: "routes-to",
          lens: "network",
          attributes: { destination: r.destination },
        });
      }
    }
    // Explicit associations; the main table implicitly covers the VPC's
    // unassociated subnets, resolved below.
    for (const subnetId of rt.subnetIds) {
      const subnetNode = ctx.index.subnet.get(subnetId);
      if (!subnetNode) continue;
      edges.push({ id: `e-rta-${rt.routeTableId}-${subnetId}`, source: subnetNode, target: id, relationship: "uses-route-table", lens: "network", attributes: {} });
      if (igwDefault) publicSubnets.add(subnetNode);
    }
    if (rt.main && igwDefault) {
      // Subnets in this VPC with no explicit association inherit the main table.
      const associated = new Set(rt.subnetIds);
      for (const [rawId, subnetNode] of ctx.index.subnet) {
        const sub = nodes.find((n) => n.id === subnetNode);
        if (sub?.parent === ctx.index.vpc.get(rt.vpcId) && !associated.has(rawId)) publicSubnets.add(subnetNode);
      }
    }
  }
  if (client.routeTables) {
    for (const n of nodes) if (n.type === "aws::ec2::subnet") n.attributes["public"] = publicSubnets.has(n.id);
  }

  for (const p of (await client.vpcPeerings?.()) ?? []) {
    const id = arn.peering(account, region, p.peeringId);
    const local = (p.requesterVpcId && ctx.index.vpc.get(p.requesterVpcId)) || (p.accepterVpcId && ctx.index.vpc.get(p.accepterVpcId));
    nodes.push({
      id,
      type: "aws::ec2::vpc-peering",
      name: nameFromTags(p.tags, p.peeringId),
      account,
      region,
      parent: local || regionId,
      tags: p.tags,
      attributes: {
        ...(p.status ? { status: p.status } : {}),
        ...(p.requesterAccount ? { requesterAccount: p.requesterAccount } : {}),
        ...(p.accepterAccount ? { accepterAccount: p.accepterAccount } : {}),
        crossAccount: Boolean(p.requesterAccount && p.accepterAccount && p.requesterAccount !== p.accepterAccount),
      },
    });
    for (const vpcId of [p.requesterVpcId, p.accepterVpcId]) {
      const vpcNode = vpcId ? ctx.index.vpc.get(vpcId) : undefined;
      if (vpcNode) edges.push({ id: `e-peer-${p.peeringId}-${vpcId}`, source: id, target: vpcNode, relationship: "peers-with", lens: "network", attributes: {} });
    }
  }

  for (const ep of (await client.vpcEndpoints?.()) ?? []) {
    const id = arn.endpoint(account, region, ep.endpointId);
    nodes.push({
      id,
      type: "aws::ec2::vpc-endpoint",
      name: nameFromTags(ep.tags, ep.serviceName.split(".").pop() ?? ep.endpointId),
      account,
      region,
      parent: (ep.vpcId && ctx.index.vpc.get(ep.vpcId)) || regionId,
      tags: ep.tags,
      attributes: { serviceName: ep.serviceName, endpointType: ep.type },
    });
  }

  for (const acl of (await client.networkAcls?.()) ?? []) {
    const id = arn.nacl(account, region, acl.aclId);
    nodes.push({
      id,
      type: "aws::ec2::network-acl",
      name: nameFromTags(acl.tags, acl.aclId),
      account,
      region,
      parent: (acl.vpcId && ctx.index.vpc.get(acl.vpcId)) || regionId,
      tags: acl.tags,
      attributes: { isDefault: acl.isDefault, entries: acl.entries },
    });
    for (const subnetId of acl.subnetIds) {
      const subnetNode = ctx.index.subnet.get(subnetId);
      if (subnetNode) edges.push({ id: `e-nacl-${acl.aclId}-${subnetId}`, source: id, target: subnetNode, relationship: "protects", lens: "network", attributes: {} });
    }
  }
}
