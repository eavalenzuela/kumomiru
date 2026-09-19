import { type CollectContext, encryptedByEdge } from "../collect.js";

/** DynamoDB tables, ECR repositories, EFS file systems, SSM parameters (metadata only). */
export async function collectData(ctx: CollectContext): Promise<void> {
  const { client, account, region, regionId, nodes } = ctx;

  for (const t of (await client.dynamoTables?.()) ?? []) {
    nodes.push({
      id: t.arn,
      type: "aws::dynamodb::table",
      name: t.name,
      account,
      region,
      parent: regionId,
      tags: t.tags,
      attributes: {
        ...(t.pitrEnabled !== undefined ? { pitrEnabled: t.pitrEnabled } : {}),
        ...(t.deletionProtection !== undefined ? { deletionProtection: t.deletionProtection } : {}),
      },
    });
    encryptedByEdge(ctx, t.arn, t.kmsKeyArn);
  }

  for (const r of (await client.ecrRepositories?.()) ?? []) {
    nodes.push({
      id: r.arn,
      type: "aws::ecr::repository",
      name: r.name,
      account,
      region,
      parent: regionId,
      tags: r.tags,
      attributes: { scanOnPush: r.scanOnPush, tagImmutability: r.tagImmutability, lifecyclePolicy: r.lifecyclePolicy },
    });
    if (r.policyStatements) {
      ctx.resources.push({ id: r.arn, type: "aws::ecr::repository", account, statements: r.policyStatements, actions: ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:*"] });
    }
  }

  for (const fs of (await client.fileSystems?.()) ?? []) {
    nodes.push({
      id: fs.arn,
      type: "aws::efs::file-system",
      name: fs.name ?? fs.fileSystemId,
      account,
      region,
      parent: regionId,
      tags: fs.tags,
      attributes: { encrypted: fs.encrypted },
    });
    encryptedByEdge(ctx, fs.arn, fs.kmsKeyId);
    if (fs.policyStatements) {
      ctx.resources.push({ id: fs.arn, type: "aws::efs::file-system", account, statements: fs.policyStatements, actions: ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:*"] });
    }
  }

  for (const p of (await client.ssmParameters?.()) ?? []) {
    // Listed for the map (a SecureString is a secret-shaped target node);
    // the value is never read and the scan role cannot read it.
    nodes.push({
      id: p.arn,
      type: "aws::ssm::parameter",
      name: p.name,
      account,
      region,
      parent: regionId,
      tags: {},
      attributes: p.type === "SecureString" ? { parameterType: p.type, secretPresent: true, valueResolved: false } : { parameterType: p.type },
    });
  }
}
