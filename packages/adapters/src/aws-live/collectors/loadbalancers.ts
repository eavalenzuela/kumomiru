import type { CollectContext } from "../collect.js";

/**
 * ELBv2 load balancers. An internet-facing LB gets a red `allows-ingress`
 * edge from each of its security groups that is open to the internet (the
 * same signal instances get); targets get `targets` dataflow edges.
 */
export async function collectLoadBalancers(ctx: CollectContext): Promise<void> {
  const { client, account, region, regionId, nodes, edges } = ctx;
  for (const lb of (await client.loadBalancers?.()) ?? []) {
    nodes.push({
      id: lb.arn,
      type: "aws::elbv2::load-balancer",
      name: lb.name,
      account,
      region,
      parent: (lb.vpcId && ctx.index.vpc.get(lb.vpcId)) || regionId,
      tags: lb.tags,
      attributes: {
        lbType: lb.type,
        scheme: lb.scheme,
        internetFacing: lb.scheme === "internet-facing",
        ...(lb.dnsName ? { dnsName: lb.dnsName } : {}),
        ...(lb.accessLogsEnabled !== undefined ? { accessLogsEnabled: lb.accessLogsEnabled } : {}),
        listeners: lb.listeners,
      },
    });
    for (const sgId of lb.securityGroupIds) {
      const sgNode = ctx.index.sg.get(sgId);
      if (!sgNode) continue;
      edges.push({ id: `e-sgm-${sgId}-${lb.name}`, source: sgNode, target: lb.arn, relationship: "protects", lens: "network", attributes: {} });
      const exposed = ctx.index.internet.get(sgId);
      if (exposed && lb.scheme === "internet-facing") {
        edges.push({
          id: `e-net-${sgId}-${lb.name}`,
          source: sgNode,
          target: lb.arn,
          relationship: "allows-ingress",
          lens: "network",
          attributes: { ports: exposed.ports, from: exposed.cidr, internetFacing: true },
        });
      }
    }
    // NLBs have no SGs by default but are internet-facing on their listener ports.
    if (lb.scheme === "internet-facing" && lb.securityGroupIds.length === 0 && lb.listeners.length > 0) {
      const igw = [...ctx.index.igw.values()][0];
      if (igw) {
        edges.push({
          id: `e-net-igw-${lb.name}`,
          source: igw,
          target: lb.arn,
          relationship: "allows-ingress",
          lens: "network",
          attributes: { ports: lb.listeners.map((l) => String(l.port)).join(","), from: "0.0.0.0/0", internetFacing: true },
        });
      }
    }
    const seen = new Set<string>();
    for (const t of lb.targets) {
      const target = t.targetType === "instance" ? ctx.index.instance.get(t.id) : t.targetType === "lambda" ? t.id : undefined;
      if (!target || seen.has(target) || !nodes.some((n) => n.id === target)) continue;
      seen.add(target);
      edges.push({
        id: `e-tg-${lb.name}-${t.id}`,
        source: lb.arn,
        target,
        relationship: "targets",
        lens: "dataflow",
        attributes: { ...(t.port !== undefined ? { port: t.port } : {}) },
      });
    }
  }
}
