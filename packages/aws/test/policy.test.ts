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
  // Every granted action is a Describe/List/Get-metadata style read.
  for (const a of policyActions()) {
    assert.match(a, /^[a-z0-9-]+:(Describe|List|Get)[A-Za-z]+$/, a);
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
