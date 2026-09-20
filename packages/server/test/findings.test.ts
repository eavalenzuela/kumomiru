import { test } from "node:test";
import assert from "node:assert/strict";

import { openDatabase } from "@kumomiru/db";
import { sampleGraph, type Finding } from "@kumomiru/graph";
import { buildApp } from "../src/app.js";

const ACCOUNT = { id: "123456789012", name: "prod", roleArn: "arn:aws:iam::123456789012:role/KumomiruScanRole" };
const T = "2026-09-19T12:00:00.000Z";

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id, severity: "high", kind: "sg-open-ssh", nodeId: `sg-${id}`, title: "SSH open", detail: "22 from 0.0.0.0/0",
    ruleId: "ec2.sg-unrestricted-ssh", source: "native", controls: [{ framework: "fsbp", id: "EC2.13" }],
    resourceType: "aws::ec2::security-group", ...over,
  };
}

/** A db seeded the way the worker would leave it after one scan. */
async function seeded() {
  const db = openDatabase(":memory:");
  db.accounts.upsert({ ...ACCOUNT, status: "active" });
  const scan = db.scans.enqueue(ACCOUNT.id, "manual");
  const snap = db.snapshots.insert({ scanId: scan.id, accountId: ACCOUNT.id, graph: { ...sampleGraph, meta: { ...sampleGraph.meta, generatedAt: T } } });
  db.ruleResults.replaceForSnapshot(snap.id, [
    { ruleId: "ec2.sg-unrestricted-ssh", resourceId: "sg-a", resourceType: "aws::ec2::security-group", status: "fail" },
    { ruleId: "ec2.sg-unrestricted-ssh", resourceId: "sg-ok", resourceType: "aws::ec2::security-group", status: "pass" },
    { ruleId: "rds.instance-publicly-accessible", resourceId: "db-1", resourceType: "aws::rds::db-instance", status: "pass" },
  ]);
  db.findings.reconcile({
    accountId: ACCOUNT.id, snapshotId: snap.id, observedAt: T,
    findings: [finding("a"), finding("b", { severity: "critical", ruleId: "rds.instance-publicly-accessible", kind: "rds-public", controls: [{ framework: "fsbp", id: "RDS.2" }] })],
    suppressions: [],
  });
  db.diffs.set(snap.id, { prevSnapshotId: null, nextSnapshotId: snap.id, nodesAdded: [{ id: "x", type: "t" }], nodesRemoved: [], nodesChanged: [], edgesAdded: [], edgesRemoved: [], findingsNew: [], findingsResolved: [] });
  const app = await buildApp({ logger: false, db, adhocIngest: false });
  return { app, db, snap, close: async () => { await app.close(); db.close(); } };
}

test("GET /findings filters by account, status, severity, rule, and control; summary counts", async () => {
  const { app, close } = await seeded();
  let res = await app.inject({ method: "GET", url: "/findings" });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().length, 2);
  assert.equal(res.json()[0].severity, "critical", "most severe first");

  res = await app.inject({ method: "GET", url: "/findings?severity=high" });
  assert.equal(res.json().length, 1);
  res = await app.inject({ method: "GET", url: "/findings?framework=fsbp&control=EC2.13" });
  assert.deepEqual(res.json().map((f: { id: string }) => f.id), ["a"]);
  res = await app.inject({ method: "GET", url: "/findings?framework=fsbp" });
  assert.equal(res.statusCode, 400);
  res = await app.inject({ method: "GET", url: "/findings?accountId=nope" });
  assert.equal(res.statusCode, 400);
  res = await app.inject({ method: "GET", url: "/findings/a" });
  assert.equal(res.json().status, "open");
  assert.equal(res.json().firstSeenAt, T);
  res = await app.inject({ method: "GET", url: "/findings/summary" });
  assert.deepEqual(res.json().open, { info: 0, low: 0, medium: 0, high: 1, critical: 1 });
  await close();
});

test("suppressions: create applies immediately, revoke lifts; unknown rule rejected", async () => {
  const { app, close } = await seeded();
  let res = await app.inject({ method: "POST", url: "/suppressions", payload: { ruleId: "no.such-rule", resourcePattern: "*", reason: "x" } });
  assert.equal(res.statusCode, 400);
  res = await app.inject({ method: "POST", url: "/suppressions", payload: { ruleId: "ec2.sg-unrestricted-ssh", resourcePattern: "sg-*", reason: "bastions are expected" } });
  assert.equal(res.statusCode, 201, res.body);
  const id = res.json().id;
  res = await app.inject({ method: "GET", url: "/findings/a" });
  assert.equal(res.json().status, "suppressed");
  assert.equal(res.json().suppressionId, id);
  res = await app.inject({ method: "GET", url: "/findings?status=open" });
  assert.equal(res.json().length, 1);
  res = await app.inject({ method: "GET", url: "/suppressions" });
  assert.equal(res.json().length, 1);

  res = await app.inject({ method: "DELETE", url: `/suppressions/${id}` });
  assert.equal(res.statusCode, 204);
  res = await app.inject({ method: "GET", url: "/findings/a" });
  assert.equal(res.json().status, "open");
  res = await app.inject({ method: "GET", url: "/suppressions" });
  assert.equal(res.json().length, 0);
  res = await app.inject({ method: "GET", url: "/suppressions?all=1" });
  assert.equal(res.json().length, 1);
  await close();
});

test("GET /rules and /controls describe the registry and catalogues", async () => {
  const { app, close } = await seeded();
  let res = await app.inject({ method: "GET", url: "/rules" });
  const ssh = res.json().find((r: { id: string }) => r.id === "ec2.sg-unrestricted-ssh");
  assert.ok(ssh);
  assert.ok(ssh.remediation.cli.includes("revoke-security-group-ingress"));
  assert.deepEqual(ssh.controls[0], { framework: "fsbp", id: "EC2.13" });
  const adopt = res.json().find((r: { id: string }) => r.id === "kumomiru.external-can-assume");
  assert.equal(adopt.adopts, "external-can-assume");

  res = await app.inject({ method: "GET", url: "/controls?framework=fsbp" });
  assert.equal(res.json().length, 1);
  assert.ok(res.json()[0].controls.some((c: { id: string }) => c.id === "EC2.13"));
  res = await app.inject({ method: "GET", url: "/controls?framework=pci" });
  assert.equal(res.statusCode, 400);
  await close();
});

test("GET /compliance rolls the latest snapshot up per control, overall and per account", async () => {
  const { app, close } = await seeded();
  let res = await app.inject({ method: "GET", url: "/compliance?framework=fsbp" });
  assert.equal(res.statusCode, 200, res.body);
  const body = res.json();
  const ec213 = body.overall.find((c: { controlId: string }) => c.controlId === "EC2.13");
  assert.equal(ec213.status, "fail");
  assert.deepEqual(ec213.failingResourceIds, ["sg-a"]);
  assert.equal(ec213.pass, 1);
  const rds2 = body.overall.find((c: { controlId: string }) => c.controlId === "RDS.2");
  assert.equal(rds2.status, "pass");
  const s31 = body.overall.find((c: { controlId: string }) => c.controlId === "S3.1");
  assert.equal(s31.status, "not-assessed");
  assert.equal(body.accounts.length, 1);
  assert.equal(body.accounts[0].accountId, ACCOUNT.id);

  res = await app.inject({ method: "GET", url: "/compliance?framework=nist-csf-2&accountId=123456789012" });
  const ir = res.json().overall.find((c: { controlId: string }) => c.controlId === "PR.IR-01");
  assert.equal(ir.status, "fail");
  res = await app.inject({ method: "GET", url: "/compliance?framework=nist-csf-2&accountId=999999999999" });
  assert.equal(res.statusCode, 404);
  res = await app.inject({ method: "GET", url: "/compliance" });
  assert.equal(res.statusCode, 400);
  await close();
});

test("GET /snapshots/:id/diff returns the stored diff", async () => {
  const { app, snap, close } = await seeded();
  let res = await app.inject({ method: "GET", url: `/snapshots/${snap.id}/diff` });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().nodesAdded.length, 1);
  res = await app.inject({ method: "GET", url: `/snapshots/nope/diff` });
  assert.equal(res.statusCode, 404);
  await close();
});
