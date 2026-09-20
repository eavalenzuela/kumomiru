import { test } from "node:test";
import assert from "node:assert/strict";

import { openDatabase } from "@kumomiru/db";
import { buildApp } from "../src/app.js";
import { renderStackSet, toRoleArn } from "../src/routes/onboarding.js";

test("GET /onboarding reports host identity, a stable external id, and org-sync state", async () => {
  const db = openDatabase(":memory:");
  const app = await buildApp({ logger: false, db, adhocIngest: false });
  let res = await app.inject({ method: "GET", url: "/onboarding" });
  assert.equal(res.statusCode, 200);
  const first = res.json();
  assert.equal(first.workerHostIdentity, null);
  assert.match(first.externalId, /^kumomiru-[0-9a-f-]{36}$/);
  assert.equal(first.scanRoleName, "KumomiruScanRole");
  assert.equal(first.orgSync.enabled, false);
  res = await app.inject({ method: "GET", url: "/onboarding" });
  assert.equal(res.json().externalId, first.externalId, "external id is generated once");

  res = await app.inject({ method: "GET", url: "/onboarding/stackset.yaml" });
  assert.equal(res.statusCode, 409, "no host identity yet");
  res = await app.inject({ method: "GET", url: "/onboarding/stackset.yaml?hostRoleArn=arn:aws:sts::111111111111:assumed-role/kumomiru-worker/i-abc" });
  assert.equal(res.statusCode, 200);
  assert.match(res.headers["content-type"] as string, /yaml/);
  assert.ok(res.body.includes("arn:aws:iam::111111111111:role/kumomiru-worker"), "assumed-role ARN normalized to the role");
  assert.ok(res.body.includes(first.externalId));
  assert.ok(res.body.includes('"ec2:DescribeInstances"'));
  assert.ok(!res.body.includes("GetSecretValue"));

  db.settings.set("worker.hostIdentity", { account: "111111111111", arn: "arn:aws:iam::111111111111:role/worker", recordedAt: "2026-09-19T00:00:00Z" });
  res = await app.inject({ method: "GET", url: "/onboarding/trust-policy.json" });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().Statement[0].Principal.AWS, "arn:aws:iam::111111111111:role/worker");
  assert.equal(res.json().Statement[0].Condition.StringEquals["sts:ExternalId"], first.externalId);

  res = await app.inject({ method: "POST", url: "/onboarding/org-sync", payload: { enabled: true, scanRoleName: "CustomScanRole" } });
  assert.equal(res.statusCode, 200);
  assert.equal(db.settings.get("org.sync.enabled"), true);
  res = await app.inject({ method: "GET", url: "/onboarding/stackset.yaml" });
  assert.ok(res.body.includes("Default: CustomScanRole"));
  await app.close();
  db.close();
});

test("renderStackSet / toRoleArn helpers", () => {
  assert.equal(toRoleArn("arn:aws:sts::123456789012:assumed-role/Worker/session"), "arn:aws:iam::123456789012:role/Worker");
  assert.equal(toRoleArn("arn:aws-us-gov:iam::123456789012:role/Worker"), "arn:aws-us-gov:iam::123456789012:role/Worker");
  const yaml = renderStackSet({ hostRoleArn: "arn:aws:iam::1:role/w", externalId: "kumomiru-x", roleName: "R" });
  assert.ok(yaml.startsWith('AWSTemplateFormatVersion: "2010-09-09"'));
  assert.ok(yaml.includes("KumomiruScanRole:"));
  assert.ok(yaml.includes('"sts:ExternalId": "kumomiru-x"'));
});
