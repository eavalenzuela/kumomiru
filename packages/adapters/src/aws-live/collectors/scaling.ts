import { marker, plaintextSecretFinding, scanText } from "../../common/sanitize.js";
import { type CollectContext, nameFromTags } from "../collect.js";

/** Launch templates (user-data scanned) and Auto Scaling groups. */
export async function collectScaling(ctx: CollectContext): Promise<void> {
  const { client, account, region, arn, regionId, nodes, edges, findings } = ctx;

  const ltNode = new Map<string, string>();
  for (const lt of (await client.launchTemplates?.()) ?? []) {
    const id = arn.launchTemplate(account, region, lt.launchTemplateId);
    ltNode.set(lt.launchTemplateId, id);
    const attributes: Record<string, unknown> = {
      ...(lt.imdsv2Required !== undefined ? { imdsv2Required: lt.imdsv2Required } : {}),
    };
    if (lt.userData) {
      const res = scanText(lt.userData);
      if (res.found) {
        attributes["userDataSecret"] = marker(res.kinds[0] ?? "secret");
        findings.push(plaintextSecretFinding(id, "launch template user-data", res.kinds));
      }
    }
    nodes.push({ id, type: "aws::ec2::launch-template", name: lt.name, account, region, parent: regionId, tags: lt.tags, attributes });
  }

  for (const asg of (await client.autoScalingGroups?.()) ?? []) {
    const parent = asg.subnetIds.map((s) => ctx.index.subnet.get(s)).find((n): n is string => Boolean(n)) ?? regionId;
    nodes.push({
      id: asg.arn,
      type: "aws::autoscaling::group",
      name: nameFromTags(asg.tags, asg.name),
      account,
      region,
      parent,
      tags: asg.tags,
      attributes: { instances: asg.instanceIds.length, ...(asg.launchConfigurationName ? { launchConfiguration: asg.launchConfigurationName } : {}) },
    });
    const lt = asg.launchTemplateId ? ltNode.get(asg.launchTemplateId) : undefined;
    if (lt) edges.push({ id: `e-asglt-${asg.name}`, source: asg.arn, target: lt, relationship: "uses", lens: "dataflow", attributes: {} });
    for (const instId of asg.instanceIds) {
      const inst = ctx.index.instance.get(instId);
      if (inst) edges.push({ id: `e-asgi-${asg.name}-${instId}`, source: asg.arn, target: inst, relationship: "manages", lens: "network", attributes: {} });
    }
  }
}
