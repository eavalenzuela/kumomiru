import type { CollectContext } from "../collect.js";

/**
 * KMS keys, Secrets Manager secrets (listed, never resolved), and the
 * region-level security settings (EBS default encryption, Config recorder,
 * GuardDuty) which land as attributes on the region container.
 */
export async function collectSecurity(ctx: CollectContext): Promise<void> {
  const { client, account, region, regionId, nodes, containers } = ctx;

  for (const key of (await client.kmsKeys?.()) ?? []) {
    ctx.index.kmsKey.set(key.arn, key.arn);
    ctx.index.kmsKey.set(key.keyId, key.arn);
    for (const a of key.aliases) ctx.index.kmsKey.set(a, key.arn);
    nodes.push({
      id: key.arn,
      type: "aws::kms::key",
      name: key.aliases[0] ?? key.keyId,
      account,
      region,
      parent: regionId,
      tags: key.tags,
      attributes: {
        manager: key.manager,
        enabled: key.enabled,
        ...(key.rotationEnabled !== undefined ? { rotationEnabled: key.rotationEnabled } : {}),
        aliases: key.aliases,
      },
    });
    if (key.policyStatements) {
      ctx.resources.push({
        id: key.arn,
        type: "aws::kms::key",
        account,
        statements: key.policyStatements,
        actions: ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:*"],
      });
    }
  }

  for (const secret of await client.secrets()) {
    nodes.push({
      id: secret.arn,
      type: "aws::secretsmanager::secret",
      name: secret.name,
      account,
      region,
      parent: regionId,
      tags: secret.tags,
      attributes: {
        secretPresent: true,
        valueResolved: false,
        ...(secret.rotationEnabled !== undefined ? { rotationEnabled: secret.rotationEnabled } : {}),
      },
    });
    if (secret.resourcePolicy) {
      ctx.resources.push({
        id: secret.arn,
        type: "aws::secretsmanager::secret",
        account,
        statements: secret.resourcePolicy,
        actions: ["secretsmanager:GetSecretValue", "secretsmanager:*"],
      });
    }
  }

  if (client.regionSettings) {
    const settings = await client.regionSettings();
    const regionNode = containers.nodes.get(regionId);
    if (regionNode) {
      Object.assign(regionNode.attributes, {
        ...(settings.ebsEncryptionByDefault !== undefined ? { ebsEncryptionByDefault: settings.ebsEncryptionByDefault } : {}),
        ...(settings.configRecorderEnabled !== undefined ? { configRecorderEnabled: settings.configRecorderEnabled } : {}),
        ...(settings.guardDutyEnabled !== undefined ? { guardDutyEnabled: settings.guardDutyEnabled } : {}),
      });
    }
  }
}
