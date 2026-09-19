import type { CollectContext } from "../collect.js";

/** CloudFront distributions (global) and API Gateway REST APIs (regional). */
export async function collectEdgeGlobal(ctx: CollectContext): Promise<void> {
  const { client, account, accountNode, nodes, edges } = ctx;
  for (const d of (await client.cloudFrontDistributions?.()) ?? []) {
    nodes.push({
      id: d.arn,
      type: "aws::cloudfront::distribution",
      name: d.domainName,
      account,
      parent: accountNode,
      tags: d.tags,
      attributes: {
        enabled: d.enabled,
        viewerProtocolPolicy: d.viewerProtocolPolicy,
        loggingEnabled: d.loggingEnabled,
        origins: d.origins,
        internetFacing: d.enabled,
      },
    });
    // An origin that is a bucket in this graph gets a dataflow edge; in a
    // global-only pass buckets are absent, so the origin list on the node is
    // the durable record.
    for (const o of d.origins) {
      if (o.type !== "s3") continue;
      const bucket = o.domainName.split(".s3")[0];
      const target = bucket ? ctx.index.bucket.get(bucket) : undefined;
      if (target) edges.push({ id: `e-cf-${d.id}-${o.id}`, source: d.arn, target, relationship: "reads-from", lens: "dataflow", attributes: {} });
    }
  }
}

export async function collectEdgeRegional(ctx: CollectContext): Promise<void> {
  const { client, account, region, regionId, nodes } = ctx;
  for (const api of (await client.restApis?.()) ?? []) {
    nodes.push({
      id: api.arn,
      type: "aws::apigateway::rest-api",
      name: api.name,
      account,
      region,
      parent: regionId,
      tags: api.tags,
      attributes: { stages: api.stages, internetFacing: api.stages.length > 0 },
    });
  }
}
