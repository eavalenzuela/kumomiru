/**
 * Phase 3 SDK collectors: the optional `DiscoveryClient` methods. Every call
 * here is a Describe/List/Get on metadata — no object bodies, no secret
 * values, no decrypt. Each module-level action list feeds the generated
 * policy; a call whose action is not declared fails the policy tests.
 */
import {
  S3Client,
  ListBucketsCommand,
  GetBucketPolicyCommand,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetBucketLoggingCommand,
  GetBucketTaggingCommand,
} from "@aws-sdk/client-s3";
import { S3ControlClient, GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand } from "@aws-sdk/client-s3-control";
import {
  EC2Client,
  DescribeVolumesCommand,
  DescribeSnapshotsCommand,
  DescribeSnapshotAttributeCommand,
  GetEbsEncryptionByDefaultCommand,
  DescribeFlowLogsCommand,
} from "@aws-sdk/client-ec2";
import {
  KMSClient,
  ListKeysCommand,
  type ListKeysCommandOutput,
  type ListAliasesCommandOutput,
  DescribeKeyCommand,
  GetKeyRotationStatusCommand,
  GetKeyPolicyCommand,
  ListAliasesCommand,
  ListResourceTagsCommand,
} from "@aws-sdk/client-kms";
import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand, GetEventSelectorsCommand } from "@aws-sdk/client-cloudtrail";
import { ConfigServiceClient, DescribeConfigurationRecorderStatusCommand } from "@aws-sdk/client-config-service";
import { GuardDutyClient, ListDetectorsCommand, GetDetectorCommand } from "@aws-sdk/client-guardduty";
import {
  IAMClient,
  GenerateCredentialReportCommand,
  GetCredentialReportCommand,
  GetAccountPasswordPolicyCommand,
  GetAccountSummaryCommand,
} from "@aws-sdk/client-iam";
import { LambdaClient, GetPolicyCommand, ListFunctionUrlConfigsCommand } from "@aws-sdk/client-lambda";
import { SecretsManagerClient, DescribeSecretCommand, GetResourcePolicyCommand } from "@aws-sdk/client-secrets-manager";

import {
  projectPolicyDocument,
  type AccountSummary,
  type CredentialReportRow,
  type DiscoveredBucket,
  type DiscoveredKmsKey,
  type DiscoveredSnapshot,
  type DiscoveredTrail,
  type DiscoveredVolume,
  type PolicyStatement,
  type RegionSettings,
} from "@kumomiru/adapters";

export const PHASE3_ACTIONS = [
  // S3 (bucket metadata only — never s3:GetObject)
  "s3:ListAllMyBuckets",
  "s3:GetBucketPolicy",
  "s3:GetBucketPolicyStatus",
  "s3:GetBucketPublicAccessBlock",
  "s3:GetEncryptionConfiguration",
  "s3:GetBucketVersioning",
  "s3:GetBucketLogging",
  "s3:GetBucketTagging",
  "s3:GetAccountPublicAccessBlock",
  // EBS
  "ec2:DescribeVolumes",
  "ec2:DescribeSnapshots",
  "ec2:DescribeSnapshotAttribute",
  "ec2:GetEbsEncryptionByDefault",
  "ec2:DescribeFlowLogs",
  // KMS (metadata only — never kms:Decrypt)
  "kms:ListKeys",
  "kms:DescribeKey",
  "kms:GetKeyRotationStatus",
  "kms:GetKeyPolicy",
  "kms:ListAliases",
  "kms:ListResourceTags",
  // CloudTrail / Config / GuardDuty
  "cloudtrail:DescribeTrails",
  "cloudtrail:GetTrailStatus",
  "cloudtrail:GetEventSelectors",
  "config:DescribeConfigurationRecorderStatus",
  "guardduty:ListDetectors",
  "guardduty:GetDetector",
  // IAM account level
  "iam:GenerateCredentialReport",
  "iam:GetCredentialReport",
  "iam:GetAccountPasswordPolicy",
  "iam:GetAccountSummary",
  // Lambda / Secrets Manager resource policies
  "lambda:GetPolicy",
  "lambda:ListFunctionUrlConfigs",
  "secretsmanager:DescribeSecret",
  "secretsmanager:GetResourcePolicy",
] as const;

/** Capabilities the SDK client provides beyond the method-implied ones. */
export const PHASE3_CAPABILITIES = ["lambda:policy", "secretsmanager:policy", "ec2:flow-log", "rds:encryption"] as const;

type Cfg = { region: string; credentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string } };

/** Run `fn`, returning `fallback` on the AWS "not found / not configured" family of errors. */
async function optional<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    const name = (err as { name?: string })?.name ?? "";
    if (/NoSuch|NotFound|NoSuchEntity|ResourceNotFound|NoSuchBucketPolicy|NoSuchPublicAccessBlockConfiguration|ServerSideEncryptionConfigurationNotFoundError/.test(name)) {
      return fallback;
    }
    throw err;
  }
}

async function mapConcurrent<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function tagsToRecord(tags: Array<{ Key?: string; Value?: string; TagKey?: string; TagValue?: string }> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tags ?? []) {
    const k = t.Key ?? t.TagKey;
    if (k) out[k] = t.Value ?? t.TagValue ?? "";
  }
  return out;
}

// --- S3 ---------------------------------------------------------------------

export function s3Collector(cfg: Cfg, accountId: () => Promise<string>) {
  const s3 = new S3Client(cfg);
  return {
    async s3Buckets(): Promise<DiscoveredBucket[]> {
      const acct = await accountId();
      const listed = await s3.send(new ListBucketsCommand({ BucketRegion: cfg.region }));
      const names = (listed.Buckets ?? []).map((b) => b.Name ?? "").filter(Boolean);
      return mapConcurrent(names, 6, async (name) => {
        const [policy, status, pab, enc, ver, log, tags] = await Promise.all([
          optional(async () => (await s3.send(new GetBucketPolicyCommand({ Bucket: name, ExpectedBucketOwner: acct }))).Policy, undefined),
          optional(async () => (await s3.send(new GetBucketPolicyStatusCommand({ Bucket: name, ExpectedBucketOwner: acct }))).PolicyStatus?.IsPublic, undefined),
          optional(async () => (await s3.send(new GetPublicAccessBlockCommand({ Bucket: name, ExpectedBucketOwner: acct }))).PublicAccessBlockConfiguration, undefined),
          optional(async () => (await s3.send(new GetBucketEncryptionCommand({ Bucket: name, ExpectedBucketOwner: acct }))).ServerSideEncryptionConfiguration, undefined),
          optional(async () => (await s3.send(new GetBucketVersioningCommand({ Bucket: name, ExpectedBucketOwner: acct }))).Status, undefined),
          optional(async () => (await s3.send(new GetBucketLoggingCommand({ Bucket: name, ExpectedBucketOwner: acct }))).LoggingEnabled, undefined),
          optional(async () => (await s3.send(new GetBucketTaggingCommand({ Bucket: name, ExpectedBucketOwner: acct }))).TagSet, undefined),
        ]);
        const sse = enc?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
        return {
          name,
          arn: `arn:aws:s3:::${name}`,
          region: cfg.region,
          ...(pab
            ? {
                publicAccessBlock: {
                  blockPublicAcls: pab.BlockPublicAcls ?? false,
                  ignorePublicAcls: pab.IgnorePublicAcls ?? false,
                  blockPublicPolicy: pab.BlockPublicPolicy ?? false,
                  restrictPublicBuckets: pab.RestrictPublicBuckets ?? false,
                },
              }
            : {}),
          ...(status !== undefined ? { policyIsPublic: status } : {}),
          ...(policy ? { policyStatements: projectPolicyDocument(policy) } : { policyStatements: [] }),
          ...(sse ? { encryption: sse } : {}),
          versioning: ver === "Enabled",
          loggingEnabled: Boolean(log),
          tags: tagsToRecord(tags),
        };
      });
    },
  };
}

// --- EBS + flow logs ------------------------------------------------------------

export function ebsCollector(cfg: Cfg) {
  const ec2 = new EC2Client(cfg);
  return {
    async ebsVolumes(): Promise<DiscoveredVolume[]> {
      const out: DiscoveredVolume[] = [];
      let token: string | undefined;
      do {
        const res = await ec2.send(new DescribeVolumesCommand(token ? { NextToken: token } : {}));
        for (const v of res.Volumes ?? []) {
          out.push({
            volumeId: v.VolumeId ?? "",
            encrypted: v.Encrypted ?? false,
            attachedInstanceIds: (v.Attachments ?? []).map((a) => a.InstanceId ?? "").filter(Boolean),
            ...(v.Size !== undefined ? { sizeGiB: v.Size } : {}),
            tags: tagsToRecord(v.Tags),
          });
        }
        token = res.NextToken;
      } while (token);
      return out;
    },
    async ebsSnapshots(): Promise<DiscoveredSnapshot[]> {
      const snaps: Array<{ id: string; volumeId?: string; encrypted: boolean; tags: Record<string, string> }> = [];
      let token: string | undefined;
      do {
        const res = await ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ["self"], ...(token ? { NextToken: token } : {}) }));
        for (const s of res.Snapshots ?? []) {
          snaps.push({ id: s.SnapshotId ?? "", ...(s.VolumeId ? { volumeId: s.VolumeId } : {}), encrypted: s.Encrypted ?? false, tags: tagsToRecord(s.Tags) });
        }
        token = res.NextToken;
      } while (token);
      return mapConcurrent(snaps, 8, async (s) => {
        const attr = await optional(
          () => ec2.send(new DescribeSnapshotAttributeCommand({ SnapshotId: s.id, Attribute: "createVolumePermission" })),
          undefined,
        );
        const isPublic = (attr?.CreateVolumePermissions ?? []).some((p) => p.Group === "all");
        return { snapshotId: s.id, ...(s.volumeId ? { volumeId: s.volumeId } : {}), encrypted: s.encrypted, public: isPublic, tags: s.tags };
      });
    },
    /** VPC ids that have at least one flow log; consumed by the base client's vpcs(). */
    async flowLogVpcIds(): Promise<Set<string>> {
      const ids = new Set<string>();
      let token: string | undefined;
      do {
        const res = await ec2.send(new DescribeFlowLogsCommand({ Filter: [{ Name: "resource-type", Values: ["VPC"] }], ...(token ? { NextToken: token } : {}) }));
        for (const f of res.FlowLogs ?? []) if (f.ResourceId) ids.add(f.ResourceId);
        token = res.NextToken;
      } while (token);
      return ids;
    },
    async ebsEncryptionByDefault(): Promise<boolean> {
      return (await ec2.send(new GetEbsEncryptionByDefaultCommand({}))).EbsEncryptionByDefault ?? false;
    },
  };
}

// --- KMS --------------------------------------------------------------------

export function kmsCollector(cfg: Cfg) {
  const kms = new KMSClient(cfg);
  return {
    async kmsKeys(): Promise<DiscoveredKmsKey[]> {
      const aliases = new Map<string, string[]>();
      let marker: string | undefined;
      do {
        const res: ListAliasesCommandOutput = await kms.send(new ListAliasesCommand(marker ? { Marker: marker } : {}));
        for (const a of res.Aliases ?? []) {
          if (a.TargetKeyId && a.AliasName) aliases.set(a.TargetKeyId, [...(aliases.get(a.TargetKeyId) ?? []), a.AliasName]);
        }
        marker = res.Truncated ? res.NextMarker : undefined;
      } while (marker);
      const ids: string[] = [];
      marker = undefined;
      do {
        const res: ListKeysCommandOutput = await kms.send(new ListKeysCommand(marker ? { Marker: marker } : {}));
        for (const k of res.Keys ?? []) if (k.KeyId) ids.push(k.KeyId);
        marker = res.Truncated ? res.NextMarker : undefined;
      } while (marker);
      return mapConcurrent(ids, 6, async (keyId) => {
        const meta = (await kms.send(new DescribeKeyCommand({ KeyId: keyId }))).KeyMetadata;
        const manager = meta?.KeyManager === "AWS" ? "AWS" : "CUSTOMER";
        const [rotation, policy, tags] = await Promise.all([
          manager === "CUSTOMER" && meta?.KeySpec === "SYMMETRIC_DEFAULT"
            ? optional(async () => (await kms.send(new GetKeyRotationStatusCommand({ KeyId: keyId }))).KeyRotationEnabled, undefined)
            : Promise.resolve(undefined),
          optional(async () => (await kms.send(new GetKeyPolicyCommand({ KeyId: keyId, PolicyName: "default" }))).Policy, undefined),
          manager === "CUSTOMER" ? optional(async () => (await kms.send(new ListResourceTagsCommand({ KeyId: keyId }))).Tags, undefined) : Promise.resolve(undefined),
        ]);
        return {
          keyId,
          arn: meta?.Arn ?? `arn:aws:kms:${cfg.region}::key/${keyId}`,
          manager,
          enabled: meta?.Enabled ?? false,
          ...(rotation !== undefined ? { rotationEnabled: rotation } : {}),
          ...(policy ? { policyStatements: projectPolicyDocument(policy) } : {}),
          aliases: aliases.get(keyId) ?? [],
          tags: tagsToRecord(tags),
        };
      });
    },
  };
}

// --- CloudTrail / Config / GuardDuty ----------------------------------------------

export function auditCollector(cfg: Cfg) {
  const ct = new CloudTrailClient(cfg);
  const config = new ConfigServiceClient(cfg);
  const gd = new GuardDutyClient(cfg);
  return {
    async cloudTrails(): Promise<DiscoveredTrail[]> {
      const trails = (await ct.send(new DescribeTrailsCommand({ includeShadowTrails: true }))).trailList ?? [];
      return mapConcurrent(trails, 4, async (t) => {
        const arn = t.TrailARN ?? t.Name ?? "";
        const [status, selectors] = await Promise.all([
          optional(() => ct.send(new GetTrailStatusCommand({ Name: arn })), undefined),
          optional(() => ct.send(new GetEventSelectorsCommand({ TrailName: arn })), undefined),
        ]);
        const mgmt =
          (selectors?.EventSelectors ?? []).some((s) => s.IncludeManagementEvents !== false && (s.ReadWriteType ?? "All") === "All") ||
          (selectors?.AdvancedEventSelectors ?? []).some((s) =>
            (s.FieldSelectors ?? []).some((f) => f.Field === "eventCategory" && (f.Equals ?? []).includes("Management")),
          ) ||
          (!selectors?.EventSelectors?.length && !selectors?.AdvancedEventSelectors?.length);
        return {
          name: t.Name ?? arn,
          arn,
          ...(t.HomeRegion ? { homeRegion: t.HomeRegion } : {}),
          isMultiRegion: t.IsMultiRegionTrail ?? false,
          isLogging: status?.IsLogging ?? false,
          logFileValidationEnabled: t.LogFileValidationEnabled ?? false,
          ...(t.KmsKeyId ? { kmsKeyId: t.KmsKeyId } : {}),
          managementEvents: mgmt,
        };
      });
    },
    async configRecorderEnabled(): Promise<boolean> {
      const res = await config.send(new DescribeConfigurationRecorderStatusCommand({}));
      return (res.ConfigurationRecordersStatus ?? []).some((r) => r.recording === true);
    },
    async guardDutyEnabled(): Promise<boolean> {
      const ids = (await gd.send(new ListDetectorsCommand({}))).DetectorIds ?? [];
      for (const id of ids) {
        const d = await gd.send(new GetDetectorCommand({ DetectorId: id }));
        if (d.Status === "ENABLED") return true;
      }
      return false;
    },
  };
}

export function regionSettingsCollector(ebs: ReturnType<typeof ebsCollector>, audit: ReturnType<typeof auditCollector>) {
  return {
    async regionSettings(): Promise<RegionSettings> {
      const [ebsDefault, configOn, gdOn] = await Promise.all([
        optional(() => ebs.ebsEncryptionByDefault(), undefined),
        optional(() => audit.configRecorderEnabled(), undefined),
        optional(() => audit.guardDutyEnabled(), undefined),
      ]);
      return {
        ...(ebsDefault !== undefined ? { ebsEncryptionByDefault: ebsDefault } : {}),
        ...(configOn !== undefined ? { configRecorderEnabled: configOn } : {}),
        ...(gdOn !== undefined ? { guardDutyEnabled: gdOn } : {}),
      };
    },
  };
}

// --- IAM account level ----------------------------------------------------------

export function iamAccountCollector(cfg: Cfg, accountId: () => Promise<string>) {
  const iam = new IAMClient(cfg);
  const s3c = new S3ControlClient(cfg);
  return {
    async accountSummary(): Promise<AccountSummary> {
      const acct = await accountId();
      const [summary, pw, pab] = await Promise.all([
        iam.send(new GetAccountSummaryCommand({})),
        optional(async () => (await iam.send(new GetAccountPasswordPolicyCommand({}))).PasswordPolicy, undefined),
        optional(async () => (await s3c.send(new GetAccountPublicAccessBlockCommand({ AccountId: acct }))).PublicAccessBlockConfiguration, undefined),
      ]);
      const m = summary.SummaryMap ?? {};
      return {
        rootMfaEnabled: (m["AccountMFAEnabled"] ?? 0) === 1,
        rootAccessKeysPresent: (m["AccountAccessKeysPresent"] ?? 0) > 0,
        passwordPolicy: pw
          ? {
              minimumLength: pw.MinimumPasswordLength ?? 0,
              requireSymbols: pw.RequireSymbols ?? false,
              requireNumbers: pw.RequireNumbers ?? false,
              requireUppercase: pw.RequireUppercaseCharacters ?? false,
              requireLowercase: pw.RequireLowercaseCharacters ?? false,
              ...(pw.MaxPasswordAge !== undefined ? { maxAgeDays: pw.MaxPasswordAge } : {}),
              ...(pw.PasswordReusePrevention !== undefined ? { reusePrevention: pw.PasswordReusePrevention } : {}),
            }
          : null,
        s3PublicAccessBlock: pab
          ? {
              blockPublicAcls: pab.BlockPublicAcls ?? false,
              ignorePublicAcls: pab.IgnorePublicAcls ?? false,
              blockPublicPolicy: pab.BlockPublicPolicy ?? false,
              restrictPublicBuckets: pab.RestrictPublicBuckets ?? false,
            }
          : null,
      };
    },
    /**
     * The credential report is generated asynchronously; poll briefly. It is
     * a CSV of per-user credential metadata — no secret material.
     */
    async credentialReport(): Promise<CredentialReportRow[]> {
      for (let attempt = 0; attempt < 10; attempt++) {
        const gen = await iam.send(new GenerateCredentialReportCommand({}));
        if (gen.State === "COMPLETE") break;
        await new Promise((r) => setTimeout(r, 1500));
      }
      const rep = await iam.send(new GetCredentialReportCommand({}));
      const csv = rep.Content ? Buffer.from(rep.Content).toString("utf8") : "";
      return parseCredentialReport(csv);
    },
  };
}

/** Parse the credential report CSV. Exported for tests. */
export function parseCredentialReport(csv: string): CredentialReportRow[] {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return [];
  const header = lines[0]!.split(",");
  const col = (row: string[], name: string) => row[header.indexOf(name)] ?? "";
  const bool = (v: string) => v.toLowerCase() === "true";
  const date = (v: string) => (v && v !== "N/A" && v !== "no_information" && v !== "not_supported" ? v : undefined);
  return lines.slice(1).map((line) => {
    const row = line.split(",");
    return {
      user: col(row, "user"),
      arn: col(row, "arn"),
      passwordEnabled: bool(col(row, "password_enabled")) || col(row, "user") === "<root_account>",
      ...(date(col(row, "password_last_used")) ? { passwordLastUsed: date(col(row, "password_last_used")) } : {}),
      mfaActive: bool(col(row, "mfa_active")),
      accessKey1Active: bool(col(row, "access_key_1_active")),
      ...(date(col(row, "access_key_1_last_rotated")) ? { accessKey1LastRotated: date(col(row, "access_key_1_last_rotated")) } : {}),
      ...(date(col(row, "access_key_1_last_used_date")) ? { accessKey1LastUsed: date(col(row, "access_key_1_last_used_date")) } : {}),
      accessKey2Active: bool(col(row, "access_key_2_active")),
      ...(date(col(row, "access_key_2_last_rotated")) ? { accessKey2LastRotated: date(col(row, "access_key_2_last_rotated")) } : {}),
      ...(date(col(row, "access_key_2_last_used_date")) ? { accessKey2LastUsed: date(col(row, "access_key_2_last_used_date")) } : {}),
    };
  });
}

// --- Lambda / Secrets Manager resource policies ---------------------------------------

export function lambdaPolicyCollector(cfg: Cfg) {
  const lambda = new LambdaClient(cfg);
  return {
    async resourcePolicy(functionName: string): Promise<PolicyStatement[]> {
      const p = await optional(async () => (await lambda.send(new GetPolicyCommand({ FunctionName: functionName }))).Policy, undefined);
      return p ? projectPolicyDocument(p) : [];
    },
    async urlAuthTypes(functionName: string): Promise<string[]> {
      const res = await optional(() => lambda.send(new ListFunctionUrlConfigsCommand({ FunctionName: functionName })), undefined);
      return (res?.FunctionUrlConfigs ?? []).map((c) => c.AuthType ?? "AWS_IAM");
    },
  };
}

export function secretPolicyCollector(cfg: Cfg) {
  const sm = new SecretsManagerClient(cfg);
  return {
    async details(secretId: string): Promise<{ rotationEnabled: boolean; resourcePolicy: PolicyStatement[] }> {
      const [desc, pol] = await Promise.all([
        optional(() => sm.send(new DescribeSecretCommand({ SecretId: secretId })), undefined),
        optional(async () => (await sm.send(new GetResourcePolicyCommand({ SecretId: secretId }))).ResourcePolicy, undefined),
      ]);
      return { rotationEnabled: desc?.RotationEnabled ?? false, resourcePolicy: pol ? projectPolicyDocument(pol) : [] };
    },
  };
}
