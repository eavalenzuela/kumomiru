import type { CollectContext } from "../collect.js";
import type { CredentialReportRow } from "../client.js";

/**
 * Global collection: IAM roles and users (principals for the assume-role
 * pass), the credential report (merged onto users; root row onto the
 * account), the account summary (root MFA / keys, password policy, account
 * S3 Public Access Block), and CloudTrail trails.
 */
export async function collectIam(ctx: CollectContext): Promise<void> {
  const { client, account, nodes, accountNode, containers } = ctx;

  const report = new Map<string, CredentialReportRow>();
  let rootRow: CredentialReportRow | undefined;
  for (const row of (await client.credentialReport?.()) ?? []) {
    if (row.user === "<root_account>") rootRow = row;
    else report.set(row.arn, row);
  }

  for (const role of await client.roles()) {
    const serviceTrust = role.trustedPrincipals.find((p) => p.type === "service");
    nodes.push({
      id: role.arn,
      type: "aws::iam::role",
      name: role.roleName,
      account,
      parent: accountNode,
      tags: role.tags,
      attributes: serviceTrust ? { trustedService: serviceTrust.value } : {},
    });
    ctx.principals.push({
      id: role.arn,
      account,
      kind: "role",
      identity: role.identityStatements ?? [],
      trust: role.trustedPrincipals.map((p) => ({
        principalValue: p.value,
        type: p.type,
        conditionKeys: p.conditionKeys ?? [],
      })),
    });
  }

  for (const user of (await client.users?.()) ?? []) {
    const row = report.get(user.arn);
    nodes.push({
      id: user.arn,
      type: "aws::iam::user",
      name: user.userName,
      account,
      parent: accountNode,
      tags: user.tags,
      attributes: row ? credentialAttributes(row) : {},
    });
    ctx.principals.push({ id: user.arn, account, kind: "user", identity: user.identityStatements ?? [] });
  }

  const accountContainer = containers.nodes.get(accountNode);
  if (accountContainer) {
    if (client.accountSummary) {
      const s = await client.accountSummary();
      Object.assign(accountContainer.attributes, {
        rootMfaEnabled: s.rootMfaEnabled,
        rootAccessKeysPresent: s.rootAccessKeysPresent,
        passwordPolicy: s.passwordPolicy,
        s3PublicAccessBlock: s.s3PublicAccessBlock,
      });
    }
    if (rootRow) {
      Object.assign(accountContainer.attributes, {
        rootMfaEnabled: rootRow.mfaActive,
        rootAccessKeysPresent: rootRow.accessKey1Active || rootRow.accessKey2Active,
        ...(rootRow.passwordLastUsed ? { rootPasswordLastUsed: rootRow.passwordLastUsed } : {}),
      });
    }
    if (client.credentialReport) accountContainer.attributes["credentialReportCollected"] = true;
  }

  for (const trail of (await client.cloudTrails?.()) ?? []) {
    nodes.push({
      id: trail.arn,
      type: "aws::cloudtrail::trail",
      name: trail.name,
      account,
      ...(trail.homeRegion ? { region: trail.homeRegion } : {}),
      parent: accountNode,
      tags: {},
      attributes: {
        isMultiRegion: trail.isMultiRegion,
        isLogging: trail.isLogging,
        logFileValidationEnabled: trail.logFileValidationEnabled,
        managementEvents: trail.managementEvents,
        ...(trail.kmsKeyId ? { kmsEncrypted: true } : { kmsEncrypted: false }),
      },
    });
  }
  if (client.cloudTrails && accountContainer) {
    const trails = nodes.filter((n) => n.type === "aws::cloudtrail::trail");
    accountContainer.attributes["cloudTrailMultiRegionLogging"] = trails.some(
      (t) => t.attributes["isMultiRegion"] === true && t.attributes["isLogging"] === true && t.attributes["managementEvents"] === true,
    );
  }
}

function credentialAttributes(row: CredentialReportRow): Record<string, unknown> {
  return {
    passwordEnabled: row.passwordEnabled,
    ...(row.passwordLastUsed ? { passwordLastUsed: row.passwordLastUsed } : {}),
    mfaActive: row.mfaActive,
    accessKey1Active: row.accessKey1Active,
    ...(row.accessKey1LastRotated ? { accessKey1LastRotated: row.accessKey1LastRotated } : {}),
    ...(row.accessKey1LastUsed ? { accessKey1LastUsed: row.accessKey1LastUsed } : {}),
    accessKey2Active: row.accessKey2Active,
    ...(row.accessKey2LastRotated ? { accessKey2LastRotated: row.accessKey2LastRotated } : {}),
    ...(row.accessKey2LastUsed ? { accessKey2LastUsed: row.accessKey2LastUsed } : {}),
  };
}
