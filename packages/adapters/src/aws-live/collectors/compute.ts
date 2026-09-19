import { marker, plaintextSecretFinding, scanText } from "../../common/sanitize.js";
import { type CollectContext, encryptedByEdge, nameFromTags } from "../collect.js";
import type { InternetIngress } from "./network.js";

/** EC2 instances, EBS volumes, EBS snapshots. */
export async function collectCompute(ctx: CollectContext, internet: InternetIngress): Promise<void> {
  const { client, account, region, arn, regionId, nodes, edges, findings } = ctx;

  for (const inst of await client.instances()) {
    const id = arn.inst(account, region, inst.instanceId);
    ctx.index.instance.set(inst.instanceId, id);
    const attributes: Record<string, unknown> = {
      ...(inst.instanceType ? { instanceType: inst.instanceType } : {}),
      ...(inst.publicIp ? { publicIp: inst.publicIp } : {}),
      ...(inst.privateIp ? { privateIp: inst.privateIp } : {}),
    };
    if (inst.userData) {
      const res = scanText(inst.userData);
      if (res.found) {
        attributes["userDataSecret"] = marker(res.kinds[0] ?? "secret");
        findings.push(plaintextSecretFinding(id, "EC2 user-data", res.kinds));
      }
    }
    nodes.push({
      id,
      type: "aws::ec2::instance",
      name: nameFromTags(inst.tags, inst.instanceId),
      account,
      region,
      parent: inst.subnetId ? (ctx.index.subnet.get(inst.subnetId) ?? regionId) : regionId,
      tags: inst.tags,
      attributes,
    });
    ctx.df.members.push({ id, groupIds: inst.securityGroupIds });

    for (const sgId of inst.securityGroupIds) {
      const sgNode = ctx.index.sg.get(sgId);
      if (sgNode) {
        edges.push({
          id: `e-sgm-${sgId}-${inst.instanceId}`,
          source: sgNode,
          target: id,
          relationship: "protects",
          lens: "network",
          attributes: {},
        });
      }
      const exposed = internet.get(sgId);
      // The source must be the SG, never the instance itself (no self-loops).
      if (exposed && sgNode) {
        edges.push({
          id: `e-net-${sgId}-${inst.instanceId}`,
          source: sgNode,
          target: id,
          relationship: "allows-ingress",
          lens: "network",
          attributes: { ports: exposed.ports, from: exposed.cidr, internetFacing: true },
        });
      }
    }
  }

  for (const vol of (await client.ebsVolumes?.()) ?? []) {
    const id = arn.volume(account, region, vol.volumeId);
    const attachedTo = vol.attachedInstanceIds.map((i) => ctx.index.instance.get(i)).find((n): n is string => Boolean(n));
    nodes.push({
      id,
      type: "aws::ec2::volume",
      name: nameFromTags(vol.tags, vol.volumeId),
      account,
      region,
      // Draw a volume inside its instance's subnet when attached; else the region.
      parent: attachedTo ? (nodes.find((n) => n.id === attachedTo)?.parent ?? regionId) : regionId,
      tags: vol.tags,
      attributes: {
        encrypted: vol.encrypted,
        attached: vol.attachedInstanceIds.length > 0,
        ...(vol.sizeGiB !== undefined ? { sizeGiB: vol.sizeGiB } : {}),
      },
    });
    for (const instId of vol.attachedInstanceIds) {
      const instNode = ctx.index.instance.get(instId);
      if (instNode) {
        edges.push({
          id: `e-vol-${vol.volumeId}-${instId}`,
          source: id,
          target: instNode,
          relationship: "attached-to",
          lens: "network",
          attributes: {},
        });
      }
    }
  }

  for (const snap of (await client.ebsSnapshots?.()) ?? []) {
    const id = arn.snapshot(account, region, snap.snapshotId);
    nodes.push({
      id,
      type: "aws::ec2::snapshot",
      name: nameFromTags(snap.tags, snap.snapshotId),
      account,
      region,
      parent: regionId,
      tags: snap.tags,
      attributes: { encrypted: snap.encrypted, public: snap.public },
    });
    encryptedByEdge(ctx, id, undefined);
  }
}
