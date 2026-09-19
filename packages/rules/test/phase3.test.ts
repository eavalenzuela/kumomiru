import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, type CloudNode, type Graph } from "@kumomiru/graph";
import { defaultRegistry, evaluate, controlStatuses } from "../src/index.js";

const ACCOUNT = "123456789012";
const NOW = "2026-09-19T00:00:00.000Z";
const CAPS = [
  "ec2:vpc", "ec2:subnet", "ec2:internet-gateway", "ec2:security-group", "ec2:instance", "rds:db-instance",
  "lambda:function", "secretsmanager:secret", "iam:role", "iam:user",
  "iam:account-summary", "iam:credential-report", "cloudtrail:trail", "account:region-settings",
  "s3:bucket", "ec2:volume", "ec2:snapshot", "kms:key", "lambda:policy", "secretsmanager:policy", "ec2:flow-log", "rds:encryption",
];

function node(id: string, type: string, attributes: Record<string, unknown> = {}, parent?: string): CloudNode {
  return { id, type, name: id, account: ACCOUNT, region: "us-east-1", ...(parent ? { parent } : {}), tags: {}, attributes };
}

function graph(): Graph {
  return parseGraph({
    nodes: [
      node("acct", "aws::account", {
        rootMfaEnabled: false, rootAccessKeysPresent: true, passwordPolicy: null,
        s3PublicAccessBlock: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: false, restrictPublicBuckets: true },
        cloudTrailMultiRegionLogging: false,
      }),
      node("region", "aws::region", { ebsEncryptionByDefault: false, configRecorderEnabled: true, guardDutyEnabled: false }, "acct"),
      node("u-old", "aws::iam::user", { passwordEnabled: true, passwordLastUsed: "2026-01-01T00:00:00Z", mfaActive: false, accessKey1Active: true, accessKey1LastRotated: "2025-01-01T00:00:00Z", accessKey1LastUsed: "2026-09-18T00:00:00Z", accessKey2Active: false }, "acct"),
      node("u-good", "aws::iam::user", { passwordEnabled: true, passwordLastUsed: "2026-09-18T00:00:00Z", mfaActive: true, accessKey1Active: true, accessKey1LastRotated: "2026-08-01T00:00:00Z", accessKey1LastUsed: "2026-09-18T00:00:00Z", accessKey2Active: false }, "acct"),
      node("u-nokeys", "aws::iam::user", { passwordEnabled: false, mfaActive: false, accessKey1Active: false, accessKey2Active: false }, "acct"),
      node("b-bad", "aws::s3::bucket", { publicAccessBlock: { blockPublicAcls: false, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true }, policyIsPublic: true, loggingEnabled: false, policyStatements: [] }, "region"),
      node("b-good", "aws::s3::bucket", { publicAccessBlock: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true }, policyIsPublic: false, loggingEnabled: true, policyStatements: [{ effect: "Deny", actions: ["s3:*"], conditionKeys: ["aws:SecureTransport"] }] }, "region"),
      node("vol-a", "aws::ec2::volume", { encrypted: false, attached: true }, "region"),
      node("vol-d", "aws::ec2::volume", { encrypted: false, attached: false }, "region"),
      node("snap", "aws::ec2::snapshot", { encrypted: false, public: true }, "region"),
      node("key", "aws::kms::key", { manager: "CUSTOMER", enabled: true, rotationEnabled: false }, "region"),
      node("key-aws", "aws::kms::key", { manager: "AWS", enabled: true }, "region"),
      node("trail", "aws::cloudtrail::trail", { isMultiRegion: false, isLogging: true, logFileValidationEnabled: false, managementEvents: true, kmsEncrypted: false }, "acct"),
      node("vpc", "aws::ec2::vpc", { flowLogsEnabled: false }, "region"),
      node("db", "aws::rds::db-instance", { publiclyAccessible: false, storageEncrypted: false }, "region"),
      node("fn", "aws::lambda::function", { urlAuthTypes: ["NONE"] }, "region"),
      node("sec", "aws::secretsmanager::secret", { secretPresent: true, valueResolved: false, rotationEnabled: false }, "region"),
    ],
    edges: [],
    findings: [
      { id: "f-pub", severity: "critical", kind: "public-resource", nodeId: "fn", title: "t", detail: "d" },
    ],
    meta: { generatedAt: NOW, source: "aws-live", provider: "aws" },
  });
}

test("phase 3 rules: each fails the offender and passes (or skips) the clean one", () => {
  const ev = evaluate(graph(), defaultRegistry(), { capabilities: CAPS });
  const status = (ruleId: string, resourceId: string) => ev.results.find((r) => r.ruleId === ruleId && r.resourceId === resourceId)?.status;

  assert.equal(status("iam.root-access-keys", "acct"), "fail");
  assert.equal(status("iam.root-mfa", "acct"), "fail");
  assert.equal(status("iam.password-policy", "acct"), "fail");
  assert.equal(status("s3.account-public-access-block", "acct"), "fail");
  assert.equal(status("cloudtrail.multi-region-trail", "acct"), "fail");

  assert.equal(status("ec2.ebs-default-encryption", "region"), "fail");
  assert.equal(status("config.recorder-enabled", "region"), "pass");
  assert.equal(status("guardduty.enabled", "region"), "fail");

  assert.equal(status("iam.user-console-mfa", "u-old"), "fail");
  assert.equal(status("iam.user-console-mfa", "u-good"), "pass");
  assert.equal(status("iam.user-console-mfa", "u-nokeys"), "not-applicable");
  assert.equal(status("iam.access-key-rotation", "u-old"), "fail");
  assert.equal(status("iam.access-key-rotation", "u-good"), "pass");
  assert.equal(status("iam.unused-credentials", "u-old"), "fail", "password unused > 90 days");
  assert.equal(status("iam.unused-credentials", "u-good"), "pass");

  assert.equal(status("s3.bucket-public-access-block", "b-bad"), "fail");
  assert.equal(status("s3.bucket-public-policy", "b-bad"), "fail");
  assert.equal(status("s3.bucket-require-tls", "b-bad"), "fail");
  assert.equal(status("s3.bucket-server-access-logging", "b-bad"), "fail");
  assert.equal(status("s3.bucket-public-access-block", "b-good"), "pass");
  assert.equal(status("s3.bucket-require-tls", "b-good"), "pass");

  assert.equal(status("ec2.ebs-volume-encrypted", "vol-a"), "fail");
  assert.equal(status("ec2.ebs-volume-encrypted", "vol-d"), "not-applicable");
  assert.equal(status("ec2.ebs-snapshot-public", "snap"), "fail");
  assert.equal(status("kms.key-rotation", "key"), "fail");
  assert.equal(status("kms.key-rotation", "key-aws"), "not-applicable");
  assert.equal(status("cloudtrail.trail-kms-encrypted", "trail"), "fail");
  assert.equal(status("cloudtrail.log-file-validation", "trail"), "fail");
  assert.equal(status("ec2.vpc-flow-logs", "vpc"), "fail");
  assert.equal(status("rds.instance-storage-encrypted", "db"), "fail");
  assert.equal(status("lambda.function-url-no-auth", "fn"), "fail");
  assert.equal(status("secretsmanager.rotation-enabled", "sec"), "fail");

  // Adoption of the resource-policy pass finding.
  const pub = ev.findings.find((f) => f.id === "f-pub")!;
  assert.equal(pub.ruleId, "kumomiru.public-resource");
  assert.equal(pub.resourceType, "aws::lambda::function");

  const detail = ev.findings.find((f) => f.ruleId === "iam.access-key-rotation")!;
  assert.match(detail.detail, /key 1 is \d+ days old/);
});

test("phase 3 rules: missing capabilities leave their resources not-assessed", () => {
  const ev = evaluate(graph(), defaultRegistry(), { capabilities: CAPS.filter((c) => !["iam:credential-report", "s3:bucket"].includes(c)) });
  assert.ok(ev.results.filter((r) => r.resourceType === "aws::iam::user").every((r) => r.status === "not-assessed"));
  assert.ok(ev.results.filter((r) => r.resourceType === "aws::s3::bucket").every((r) => r.status === "not-assessed"));
  assert.ok(ev.notAssessedRules.includes("s3.bucket-public-policy"));
  assert.ok(ev.results.some((r) => r.ruleId === "iam.root-mfa" && r.status === "fail"), "account-summary rules still run");
});

test("FSBP roll-up covers the phase 3 controls", () => {
  const reg = defaultRegistry();
  const ev = evaluate(graph(), reg, { capabilities: CAPS });
  const byId = new Map(controlStatuses("fsbp", ev.results, reg).map((c) => [c.controlId, c]));
  for (const id of ["IAM.3", "IAM.4", "IAM.5", "IAM.7", "IAM.8", "IAM.9", "S3.1", "S3.2", "S3.5", "S3.8", "S3.9", "EC2.1", "EC2.3", "EC2.6", "EC2.7", "KMS.4", "CloudTrail.1", "CloudTrail.2", "CloudTrail.4", "GuardDuty.1", "Lambda.1", "SecretsManager.1", "RDS.3"]) {
    assert.equal(byId.get(id)?.status, "fail", id);
  }
  assert.equal(byId.get("Config.1")!.status, "pass");
  assert.equal(byId.get("ELB.1")!.status, "not-assessed", "unmapped tranche-B control visible as a gap");
  const mapped = [...byId.values()].filter((c) => c.ruleIds.length > 0).length;
  assert.ok(mapped >= 29, `mapped ${mapped}`);
});
