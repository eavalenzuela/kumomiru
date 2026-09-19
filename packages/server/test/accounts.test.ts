import { test } from "node:test";
import assert from "node:assert/strict";

import { openDatabase } from "@kumomiru/db";
import { parseGraph, sampleGraph } from "@kumomiru/graph";
import { buildApp } from "../src/app.js";

const ACCOUNT = {
  id: "123456789012",
  name: "prod",
  roleArn: "arn:aws:iam::123456789012:role/KumomiruScanRole",
  externalId: "ext-1",
};

function appWithDb() {
  const db = openDatabase(":memory:");
  const app = buildApp({ logger: false, db, adhocIngest: true });
  return { app, db, close: async () => { await app.close(); db.close(); } };
}

test("POST /accounts validates and registers; GET lists with status", async () => {
  const { app, close } = appWithDb();
  let res = await app.inject({ method: "POST", url: "/accounts", payload: ACCOUNT });
  assert.equal(res.statusCode, 201, res.body);
  assert.equal(res.json().status, "pending");

  // Upsert of the same id is a 200, and keeps status.
  res = await app.inject({ method: "POST", url: "/accounts", payload: { ...ACCOUNT, name: "prod2" } });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().name, "prod2");

  res = await app.inject({ method: "GET", url: "/accounts" });
  assert.equal(res.json().length, 1);
  assert.equal(res.json()[0].latestSnapshot, null);
  assert.equal(res.json()[0].activeScan, null);

  // Validation: bad id, role in another account, bad cron, bad region.
  for (const bad of [
    { ...ACCOUNT, id: "123" },
    { ...ACCOUNT, roleArn: "arn:aws:iam::999999999999:role/X" },
    { ...ACCOUNT, scheduleCron: "whenever" },
    { ...ACCOUNT, regions: ["mars-1"] },
  ]) {
    res = await app.inject({ method: "POST", url: "/accounts", payload: bad });
    assert.equal(res.statusCode, 400, JSON.stringify(bad));
  }
  await close();
});

test("scan requests are queued once; latest returns 404 until a snapshot exists", async () => {
  const { app, db, close } = appWithDb();
  await app.inject({ method: "POST", url: "/accounts", payload: ACCOUNT });

  let res = await app.inject({ method: "GET", url: `/accounts/${ACCOUNT.id}/latest` });
  assert.equal(res.statusCode, 404);
  assert.equal(res.json().error, "no_snapshot");

  res = await app.inject({ method: "POST", url: `/accounts/${ACCOUNT.id}/scans`, payload: { trigger: "verify" } });
  assert.equal(res.statusCode, 202);
  const scanId = res.json().id;
  assert.equal(res.json().trigger, "verify");
  res = await app.inject({ method: "POST", url: `/accounts/${ACCOUNT.id}/scans` });
  assert.equal(res.json().id, scanId, "idempotent while active");

  // Simulate the worker completing the scan and storing a snapshot.
  const claimed = db.scans.claimNext("w")!;
  db.scans.finish(claimed.id, { status: "ok" });
  const snap = db.snapshots.insert({ scanId: claimed.id, accountId: ACCOUNT.id, graph: sampleGraph });

  res = await app.inject({ method: "GET", url: `/accounts/${ACCOUNT.id}/latest` });
  assert.equal(res.statusCode, 200);
  const graph = parseGraph(res.json());
  assert.equal(graph.meta.snapshotId, snap.id);

  res = await app.inject({ method: "GET", url: `/accounts/${ACCOUNT.id}/latest?redacted=1` });
  const vpc = res.json().nodes.find((n: { type: string }) => n.type === "aws::ec2::vpc");
  assert.equal(vpc.tags.Name, "[redacted]");

  res = await app.inject({ method: "GET", url: `/snapshots/${snap.id}` });
  assert.equal(res.json().scanId, claimed.id);
  res = await app.inject({ method: "GET", url: `/snapshots/${snap.id}/graph` });
  parseGraph(res.json());
  res = await app.inject({ method: "GET", url: `/scans/${claimed.id}` });
  assert.equal(res.json().status, "ok");
  res = await app.inject({ method: "GET", url: `/accounts/${ACCOUNT.id}/scans` });
  assert.equal(res.json().length, 1);
  res = await app.inject({ method: "GET", url: `/accounts/${ACCOUNT.id}` });
  assert.equal(res.json().latestSnapshot.id, snap.id);

  res = await app.inject({ method: "DELETE", url: `/accounts/${ACCOUNT.id}` });
  assert.equal(res.statusCode, 204);
  res = await app.inject({ method: "GET", url: `/snapshots/${snap.id}` });
  assert.equal(res.statusCode, 404, "cascade");
  await close();
});

test("ad-hoc ingest routes disappear when the flag is off", async () => {
  const db = openDatabase(":memory:");
  const app = buildApp({ logger: false, db, adhocIngest: false });
  let res = await app.inject({ method: "POST", url: "/map/terraform", payload: {} });
  assert.equal(res.statusCode, 404);
  res = await app.inject({ method: "POST", url: "/map/live", payload: {} });
  assert.equal(res.statusCode, 404);
  // The persisted path and the sample stay available.
  res = await app.inject({ method: "GET", url: "/accounts" });
  assert.equal(res.statusCode, 200);
  res = await app.inject({ method: "GET", url: "/sample" });
  assert.equal(res.statusCode, 200);
  await app.close();
  db.close();
});

test("without a db the server is the stateless mapper: no account routes", async () => {
  const app = buildApp({ logger: false, adhocIngest: true });
  const res = await app.inject({ method: "GET", url: "/accounts" });
  assert.equal(res.statusCode, 404);
  await app.close();
});
