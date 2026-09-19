import { marker, plaintextSecretFinding, scanRecord } from "../../common/sanitize.js";
import type { CollectContext } from "../collect.js";

/** ECS clusters/services/task definitions and EKS clusters. */
export async function collectContainers(ctx: CollectContext): Promise<void> {
  const { client, account, region, regionId, nodes, edges, findings } = ctx;

  const taskDefNode = new Map<string, string>();
  for (const td of (await client.ecsTaskDefinitions?.()) ?? []) {
    const attributes: Record<string, unknown> = { containers: td.containers.map((c) => c.name) };
    const kinds = new Set<string>();
    for (const c of td.containers) {
      const res = scanRecord(c.environment);
      if (res.found) for (const k of res.kinds) kinds.add(k);
    }
    if (kinds.size) {
      attributes["environmentSecret"] = marker([...kinds][0] ?? "secret");
      findings.push(plaintextSecretFinding(td.arn, "ECS task definition environment variables", [...kinds]));
    }
    taskDefNode.set(td.arn, td.arn);
    nodes.push({ id: td.arn, type: "aws::ecs::task-definition", name: td.family, account, region, parent: regionId, tags: td.tags, attributes });
  }

  for (const cluster of (await client.ecsClusters?.()) ?? []) {
    nodes.push({ id: cluster.arn, type: "aws::ecs::cluster", name: cluster.name, account, region, parent: regionId, tags: cluster.tags, attributes: { services: cluster.services.length } });
    for (const svc of cluster.services) {
      const parent = svc.subnetIds.map((s) => ctx.index.subnet.get(s)).find((n): n is string => Boolean(n)) ?? cluster.arn;
      nodes.push({
        id: svc.arn,
        type: "aws::ecs::service",
        name: svc.name,
        account,
        region,
        parent,
        tags: {},
        attributes: { cluster: cluster.name, assignPublicIp: svc.assignPublicIp, ...(svc.launchType ? { launchType: svc.launchType } : {}) },
      });
      edges.push({ id: `e-ecs-${cluster.name}-${svc.name}`, source: cluster.arn, target: svc.arn, relationship: "contains", lens: "dataflow", attributes: {} });
      if (svc.taskDefinitionArn && taskDefNode.has(svc.taskDefinitionArn)) {
        edges.push({ id: `e-ecstd-${svc.name}`, source: svc.arn, target: svc.taskDefinitionArn, relationship: "runs", lens: "dataflow", attributes: {} });
      }
      ctx.df.members.push({ id: svc.arn, groupIds: svc.securityGroupIds });
      for (const sgId of svc.securityGroupIds) {
        const sgNode = ctx.index.sg.get(sgId);
        if (!sgNode) continue;
        edges.push({ id: `e-sgm-${sgId}-${svc.name}`, source: sgNode, target: svc.arn, relationship: "protects", lens: "network", attributes: {} });
        const exposed = ctx.index.internet.get(sgId);
        if (exposed && svc.assignPublicIp) {
          edges.push({ id: `e-net-${sgId}-${svc.name}`, source: sgNode, target: svc.arn, relationship: "allows-ingress", lens: "network", attributes: { ports: exposed.ports, from: exposed.cidr, internetFacing: true } });
        }
      }
    }
  }

  for (const eks of (await client.eksClusters?.()) ?? []) {
    nodes.push({
      id: eks.arn,
      type: "aws::eks::cluster",
      name: eks.name,
      account,
      region,
      parent: (eks.vpcId && ctx.index.vpc.get(eks.vpcId)) || regionId,
      tags: eks.tags,
      attributes: {
        ...(eks.version ? { version: eks.version } : {}),
        endpointPublicAccess: eks.endpointPublicAccess,
        endpointPrivateAccess: eks.endpointPrivateAccess,
        publicAccessCidrs: eks.publicAccessCidrs,
        loggingEnabled: eks.loggingEnabled,
      },
    });
    for (const sgId of eks.securityGroupIds) {
      const sgNode = ctx.index.sg.get(sgId);
      if (sgNode) edges.push({ id: `e-sgm-${sgId}-${eks.name}`, source: sgNode, target: eks.arn, relationship: "protects", lens: "network", attributes: {} });
    }
  }
}
