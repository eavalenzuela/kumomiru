import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  LEAST_PRIVILEGE_POLICY,
  DENIED_ACTION_PREFIXES,
  deniedActionsPresent,
  policyActions,
} from "../src/policy.js";
import { parseCredentialReport } from "../src/collectors.js";

test("docs/least-privilege-policy.json matches the in-code policy (run pnpm policy:gen)", () => {
  const onDisk = JSON.parse(
    readFileSync(
      fileURLToPath(
        new URL("../../../docs/least-privilege-policy.json", import.meta.url),
      ),
      "utf8",
    ),
  );
  assert.deepEqual(onDisk, LEAST_PRIVILEGE_POLICY);
});

test("the scan policy never grants a data-plane read", () => {
  assert.deepEqual(deniedActionsPresent(), []);
  // The denylist itself must keep the two original guarantees.
  assert.ok(DENIED_ACTION_PREFIXES.includes("secretsmanager:GetSecretValue"));
  assert.ok(DENIED_ACTION_PREFIXES.includes("ssm:GetParameter"));
  // Every granted action is a Describe/List/Get-metadata style read. The one
  // exception is iam:GenerateCredentialReport: it asks IAM to build the
  // credential-metadata CSV (no resource changes, no secrets) and is the only
  // way to obtain it.
  const READ_SHAPE = /^[a-z0-9-]+:(Describe|List|Get)[A-Za-z]+$/;
  // apigateway:GET is how API Gateway names every read.
  const EXCEPTIONS = new Set(["iam:GenerateCredentialReport", "apigateway:GET"]);
  for (const a of policyActions()) {
    assert.ok(READ_SHAPE.test(a) || EXCEPTIONS.has(a), a);
  }
  // No duplicates, and the calls the client makes are all present.
  assert.equal(new Set(policyActions()).size, policyActions().length);
  for (const must of [
    "sts:GetCallerIdentity",
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceAttribute",
    "ec2:DescribeRegions",
    "iam:GetAccountAuthorizationDetails",
  ]) {
    assert.ok(policyActions().includes(must), must);
  }
});

test("policy covers the Phase 3 collectors and still has no data-plane read", () => {
  for (const must of [
    "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock",
    "ec2:DescribeVolumes", "ec2:DescribeSnapshotAttribute", "ec2:GetEbsEncryptionByDefault", "ec2:DescribeFlowLogs",
    "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "cloudtrail:DescribeTrails", "guardduty:GetDetector",
    "config:DescribeConfigurationRecorderStatus", "iam:GetCredentialReport", "iam:GetAccountSummary",
    "lambda:GetPolicy", "lambda:ListFunctionUrlConfigs", "secretsmanager:GetResourcePolicy",
  ]) {
    assert.ok(policyActions().includes(must), must);
  }
  for (const never of ["s3:GetObject", "kms:Decrypt", "secretsmanager:GetSecretValue", "lambda:GetFunction", "ssm:GetParameter"]) {
    assert.ok(!policyActions().some((a) => a.toLowerCase().startsWith(never.toLowerCase())), never);
  }
  assert.deepEqual(policyActions(), [...policyActions()].sort(), "sorted for stable diffs");
});

test("parseCredentialReport reads the IAM CSV, root row included", () => {
  const csv = [
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated",
    "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,2026-09-01T00:00:00+00:00,not_supported,not_supported,false,true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
    "alice,arn:aws:iam::123456789012:user/alice,2021-01-01T00:00:00+00:00,true,2026-09-10T00:00:00+00:00,2026-01-01T00:00:00+00:00,N/A,true,true,2025-01-01T00:00:00+00:00,2026-09-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
  ].join("\n");
  const rows = parseCredentialReport(csv);
  assert.equal(rows.length, 2);
  const root = rows[0]!;
  assert.equal(root.user, "<root_account>");
  assert.equal(root.mfaActive, false);
  assert.equal(root.accessKey1Active, true);
  assert.equal(root.passwordEnabled, true, "root always has a password");
  const alice = rows[1]!;
  assert.equal(alice.mfaActive, true);
  assert.equal(alice.accessKey1LastRotated, "2025-01-01T00:00:00+00:00");
  assert.equal(alice.accessKey2LastRotated, undefined);
  assert.deepEqual(parseCredentialReport(""), []);
});
