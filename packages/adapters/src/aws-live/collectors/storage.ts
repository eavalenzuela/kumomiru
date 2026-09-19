import { type CollectContext, encryptedByEdge } from "../collect.js";

/** S3 buckets located in this region. */
export async function collectStorage(ctx: CollectContext): Promise<void> {
  const { client, account, region, regionId, nodes } = ctx;
  for (const b of (await client.s3Buckets?.()) ?? []) {
    ctx.index.bucket.set(b.name, b.arn);
    nodes.push({
      id: b.arn,
      type: "aws::s3::bucket",
      name: b.name,
      account,
      region,
      parent: regionId,
      tags: b.tags,
      attributes: {
        ...(b.publicAccessBlock ? { publicAccessBlock: b.publicAccessBlock } : {}),
        ...(b.policyIsPublic !== undefined ? { policyIsPublic: b.policyIsPublic } : {}),
        ...(b.encryption ? { encryption: b.encryption } : { encryption: "none" }),
        ...(b.versioning !== undefined ? { versioning: b.versioning } : {}),
        ...(b.loggingEnabled !== undefined ? { loggingEnabled: b.loggingEnabled } : {}),
        ...(b.policyStatements ? { policyStatements: b.policyStatements } : {}),
      },
    });
    if (b.policyStatements) {
      ctx.resources.push({
        id: b.arn,
        type: "aws::s3::bucket",
        account,
        statements: b.policyStatements,
        actions: ["s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:*"],
        resourceAliases: [`${b.arn}/*`],
      });
    }
    encryptedByEdge(ctx, b.arn, undefined);
  }
}
