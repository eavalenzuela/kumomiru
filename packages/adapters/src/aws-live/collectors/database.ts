import type { CollectContext } from "../collect.js";

/** RDS instances. */
export async function collectDatabase(ctx: CollectContext): Promise<void> {
  const { client, account, region, arn, regionId, nodes } = ctx;
  for (const db of await client.dbInstances()) {
    const id = arn.db(account, region, db.dbInstanceIdentifier);
    const parentSubnet = db.subnetIds.map((s) => ctx.index.subnet.get(s)).find((n): n is string => Boolean(n));
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
}
