import { test } from "node:test";
import assert from "node:assert/strict";

import { sampleGraph } from "@kumomiru/graph";
import { openDatabase } from "../src/index.js";

const ACCOUNT = {
  id: "123456789012",
  name: "prod",
  roleArn: "arn:aws:iam::123456789012:role/KumomiruScanRole",
  externalId: "ext-1",
};

function fresh(now?: () => Date) {
  return openDatabase(":memory:", now ? { now } : {});
}

test("accounts: upsert, get, list, status, remove", () => {
  const db = fresh();
  const a = db.accounts.upsert(ACCOUNT);
  assert.equal(a.status, "pending");
  assert.equal(a.scheduleCron, "0 */6 * * *");
  assert.equal(a.regions, null);
  assert.equal(a.onboarding, "manual");

  db.accounts.setStatus(a.id, "active");
  // Upsert without status keeps the current status; with explicit regions.
  const b = db.accounts.upsert({ ...ACCOUNT, name: "prod-renamed", regions: ["us-east-1"] });
  assert.equal(b.status, "active");
  assert.equal(b.name, "prod-renamed");
  assert.deepEqual(b.regions, ["us-east-1"]);
  assert.equal(db.accounts.list().length, 1);
  assert.ok(db.accounts.remove(a.id));
  assert.equal(db.accounts.get(a.id), null);
  db.close();
});

test("scans: enqueue is idempotent while active; claimNext is single-flight per account", () => {
  const db = fresh();
  db.accounts.upsert(ACCOUNT);
  db.accounts.upsert({ ...ACCOUNT, id: "210987654321", name: "dev" });

  const s1 = db.scans.enqueue(ACCOUNT.id, "manual");
  const again = db.scans.enqueue(ACCOUNT.id, "schedule");
  assert.equal(again.id, s1.id, "second enqueue returns the active scan");
  const s2 = db.scans.enqueue("210987654321", "schedule");

  const c1 = db.scans.claimNext("w1")!;
  assert.equal(c1.id, s1.id);
  assert.equal(c1.status, "running");
  assert.equal(c1.workerId, "w1");
  // Same account cannot be claimed twice; the other account can.
  db.scans.enqueue(ACCOUNT.id, "manual"); // returns the running one, no new row
  const c2 = db.scans.claimNext("w2")!;
  assert.equal(c2.id, s2.id);
  assert.equal(db.scans.claimNext("w3"), null);

  db.scans.setRegions(c1.id, ["us-east-1", "eu-west-1"]);
  db.scans.finish(c1.id, { status: "partial", error: "eu-west-1: throttled", stats: { regions: 2 } });
  const done = db.scans.get(c1.id)!;
  assert.equal(done.status, "partial");
  assert.deepEqual(done.regions, ["us-east-1", "eu-west-1"]);
  assert.deepEqual(done.stats, { regions: 2 });
  assert.ok(done.finishedAt);
  assert.equal(db.scans.active(ACCOUNT.id), null);
  assert.equal(db.scans.lastStartedAt(ACCOUNT.id), done.startedAt);
  assert.equal(db.scans.listForAccount(ACCOUNT.id).length, 1);
  db.close();
});

test("snapshots: insert stamps meta ids, chains prev, latest wins by generatedAt", () => {
  const db = fresh();
  db.accounts.upsert(ACCOUNT);
  const scan = db.scans.enqueue(ACCOUNT.id, "manual");

  const g1 = { ...sampleGraph, meta: { ...sampleGraph.meta, generatedAt: "2026-09-19T01:00:00.000Z" } };
  const g2 = { ...sampleGraph, meta: { ...sampleGraph.meta, generatedAt: "2026-09-19T02:00:00.000Z" } };
  const s1 = db.snapshots.insert({ scanId: scan.id, accountId: ACCOUNT.id, graph: g1 });
  const s2 = db.snapshots.insert({ scanId: scan.id, accountId: ACCOUNT.id, graph: g2 });

  assert.equal(s1.prevSnapshotId, null);
  assert.equal(s2.prevSnapshotId, s1.id);
  assert.equal(s1.nodeCount, sampleGraph.nodes.length);
  assert.equal(db.snapshots.latestForAccount(ACCOUNT.id)!.id, s2.id);
  assert.equal(db.snapshots.listForAccount(ACCOUNT.id).length, 2);

  const stored = db.snapshots.getGraph(s2.id)!;
  assert.equal(stored.meta.snapshotId, s2.id);
  assert.equal(stored.meta.scanId, scan.id);
  assert.equal(stored.nodes.length, sampleGraph.nodes.length);
  assert.equal(db.snapshots.getGraph("nope"), null);
  db.close();
});

test("deleting an account cascades to its scans and snapshots", () => {
  const db = fresh();
  db.accounts.upsert(ACCOUNT);
  const scan = db.scans.enqueue(ACCOUNT.id, "manual");
  db.snapshots.insert({ scanId: scan.id, accountId: ACCOUNT.id, graph: sampleGraph });
  db.accounts.remove(ACCOUNT.id);
  assert.equal(db.scans.get(scan.id), null);
  assert.equal(db.snapshots.latestForAccount(ACCOUNT.id), null);
  db.close();
});

test("settings round-trip JSON", () => {
  const db = fresh();
  assert.equal(db.settings.get("ui.defaultHome"), null);
  db.settings.set("ui.defaultHome", { view: "map" });
  assert.deepEqual(db.settings.get("ui.defaultHome"), { view: "map" });
  db.close();
});

test("leases: exclusive until expiry, renewable by holder, releasable", () => {
  let t = 1_000_000;
  const db = fresh(() => new Date(t));
  assert.ok(db.leases.acquire("scheduler", "w1", 10_000));
  assert.ok(!db.leases.acquire("scheduler", "w2", 10_000), "held by w1");
  assert.ok(db.leases.acquire("scheduler", "w1", 10_000), "holder can renew");
  t += 10_001;
  assert.ok(db.leases.acquire("scheduler", "w2", 10_000), "expired lease is free");
  db.leases.release("scheduler", "w1"); // not the holder: no-op
  assert.ok(!db.leases.acquire("scheduler", "w3", 10_000));
  db.leases.release("scheduler", "w2");
  assert.ok(db.leases.acquire("scheduler", "w3", 10_000));
  db.close();
});

test("users: upsert on login by issuer+subject, role preserved, admin override, disable", () => {
  const db = fresh();
  const a = db.users.upsertOnLogin({ email: "Alice@Example.com", name: "Alice", idpSubject: "sub-1", idpIssuer: "https://idp" });
  assert.equal(a.email, "alice@example.com");
  assert.equal(a.role, "viewer");
  const again = db.users.upsertOnLogin({ email: "alice@example.com", name: "Alice B", idpSubject: "sub-1", idpIssuer: "https://idp" });
  assert.equal(again.id, a.id);
  assert.equal(again.name, "Alice B");
  assert.equal(again.role, "viewer", "role kept when not given");
  const admin = db.users.upsertOnLogin({ email: "alice@example.com", idpSubject: "sub-1", idpIssuer: "https://idp", role: "admin" });
  assert.equal(admin.role, "admin");
  assert.ok(db.users.setRole(a.id, "viewer"));
  assert.equal(db.users.get(a.id)!.role, "viewer");
  assert.ok(db.users.setDisabled(a.id, true));
  assert.equal(db.users.getByEmail("ALICE@example.com")!.disabled, true);
  assert.equal(db.users.count(), 1);
  db.close();
});

test("accounts: organization fields and schedule preservation on sync upsert", () => {
  const db = fresh();
  db.accounts.upsert({ ...ACCOUNT, scheduleCron: "0 2 * * *" });
  const synced = db.accounts.upsert({ ...ACCOUNT, name: "prod (org)", onboarding: "organizations", orgId: "o-abc", ouPath: "Root/Workloads/Prod", email: "root@example.com" });
  assert.equal(synced.orgId, "o-abc");
  assert.equal(synced.ouPath, "Root/Workloads/Prod");
  assert.equal(synced.scheduleCron, "0 2 * * *", "sync without a schedule keeps the operator's");
  assert.equal(synced.onboarding, "organizations");
  db.close();
});
