import type { CollectContext } from "../collect.js";

/** RDS instances, clusters, snapshots. */
export async function collectDatabase(ctx: CollectContext): Promise<void> {
  const { client, account, region, arn, regionId, nodes, edges } = ctx;
  const instanceNode = new Map<string, string>();
  for (const db of await client.dbInstances()) {
    const id = arn.db(account, region, db.dbInstanceIdentifier);
    const parentSubnet = db.subnetIds.map((s) => ctx.index.subnet.get(s)).find((n): n is string => Boolean(n));
    instanceNode.set(db.dbInstanceIdentifier, id);
    nodes.push({
      id,
      type: "aws::rds::db-instance",
      name: db.dbInstanceIdentifier,
      account,
      region,
      parent: parentSubnet ?? regionId,
      tags: db.tags,
      attributes: {
        ...(db.engine ? { engine: db.engine } : {}),
        ...(db.port ? { port: db.port } : {}),
        publiclyAccessible: db.publiclyAccessible ?? false,
        ...(db.storageEncrypted !== undefined ? { storageEncrypted: db.storageEncrypted } : {}),
      },
    });
  }

  for (const c of (await client.dbClusters?.()) ?? []) {
    nodes.push({
      id: c.arn,
      type: "aws::rds::db-cluster",
      name: c.identifier,
      account,
      region,
      parent: regionId,
      tags: c.tags,
      attributes: {
        ...(c.engine ? { engine: c.engine } : {}),
        ...(c.storageEncrypted !== undefined ? { storageEncrypted: c.storageEncrypted } : {}),
        members: c.memberInstanceIdentifiers.length,
      },
    });
    for (const m of c.memberInstanceIdentifiers) {
      const target = instanceNode.get(m);
      if (target) {
        edges.push({ id: `e-rdsm-${c.identifier}-${m}`, source: c.arn, target, relationship: "contains", lens: "dataflow", attributes: {} });
      }
    }
  }

  for (const snap of (await client.dbSnapshots?.()) ?? []) {
    nodes.push({
      id: snap.arn,
      type: "aws::rds::db-snapshot",
      name: snap.identifier,
      account,
      region,
      parent: regionId,
      tags: snap.tags,
      attributes: { kind: snap.kind, encrypted: snap.encrypted, public: snap.public },
    });
  }
}
