import { test } from "node:test";
import assert from "node:assert/strict";

import { openDatabase } from "@kumomiru/db";
import type { AwsCredentials } from "@kumomiru/adapters";
import { Scheduler, runScan, silentLogger, type WorkerDeps } from "../src/index.js";
import { fakeClientFactory } from "./fake-client.js";

const ACCOUNT = {
  id: "123456789012",
  name: "prod",
  roleArn: "arn:aws:iam::123456789012:role/KumomiruScanRole",
  externalId: "ext-1",
};

function fakeDeps(over: Partial<WorkerDeps> = {}, opts: { failRegion?: string } = {}) {
  const { factory, calls } = fakeClientFactory(opts);
  const assumed: unknown[] = [];
  const deps: WorkerDeps = {
    sts: {
      assumeRole: async (input) => {
        assumed.push(input);
        return {
          accessKeyId: "ASIATEMP",
          secretAccessKey: "temp-secret",
          sessionToken: "temp-token",
          region: input.region,
        };
      },
      hostIdentity: async () => ({ account: "111111111111", arn: "arn:aws:iam::111111111111:role/worker" }),
    },
    listRegions: async () => ["eu-west-1", "us-east-1"],
    makeClient: factory,
    now: () => new Date("2026-09-19T12:00:00Z"),
    workerId: "w-test",
    stsRegion: "us-east-1",
    ...over,
  };
  return { deps, calls, assumed };
}

test("runScan: assumes the role once, scans every region, persists a merged snapshot", async () => {
  const db = openDatabase(":memory:");
  const { deps, calls, assumed } = fakeDeps();
  db.accounts.upsert({ ...ACCOUNT, status: "active" });
  const scan = db.scans.claimNext("w-test") ?? db.scans.enqueue(ACCOUNT.id, "manual");
  const claimed = db.scans.claimNext("w-test") ?? scan;

  await runScan(claimed, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);

  assert.equal(assumed.length, 1, "one AssumeRole per scan");
  assert.deepEqual((assumed[0] as { externalId?: string }).externalId, "ext-1");
  // 1 global pass + 2 regional passes, each with its own borrowed copy.
  assert.equal(calls.length, 3);
  assert.deepEqual(calls.map((c) => c.region).sort(), ["eu-west-1", "us-east-1", "us-east-1"]);

  const done = db.scans.get(claimed.id)!;
  assert.equal(done.status, "ok", done.error ?? "");
  assert.deepEqual(done.regions, ["eu-west-1", "us-east-1"]);
  const snap = db.snapshots.latestForAccount(ACCOUNT.id)!;
  assert.equal(snap.scanId, claimed.id);
  const graph = db.snapshots.getGraph(snap.id)!;
  assert.deepEqual(graph.meta.regions, ["eu-west-1", "us-east-1"]);
  assert.equal(graph.meta.accountId, ACCOUNT.id);
  assert.equal(graph.nodes.filter((n) => n.type === "aws::region").length, 2);
  assert.equal(graph.nodes.filter((n) => n.type === "aws::ec2::instance").length, 2);
  assert.equal(graph.nodes.filter((n) => n.type === "aws::iam::role").length, 1);
  assert.ok(graph.findings.some((f) => f.kind === "external-can-assume"));
  db.close();
});

test("runScan: a failing region yields a partial scan with the other regions persisted", async () => {
  const db = openDatabase(":memory:");
  const { deps } = fakeDeps({}, { failRegion: "eu-west-1" });
  db.accounts.upsert({ ...ACCOUNT, status: "active" });
  db.scans.enqueue(ACCOUNT.id, "manual");
  const scan = db.scans.claimNext("w-test")!;

  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);

  const done = db.scans.get(scan.id)!;
  assert.equal(done.status, "partial");
  assert.match(done.error ?? "", /eu-west-1: Error: ThrottlingException/);
  assert.deepEqual(done.stats?.["failedRegions"], ["eu-west-1"]);
  const graph = db.snapshots.getGraph(db.snapshots.latestForAccount(ACCOUNT.id)!.id)!;
  assert.deepEqual(graph.meta.regions, ["us-east-1"]);
  assert.equal(graph.nodes.filter((n) => n.type === "aws::ec2::instance").length, 1);
  db.close();
});

test("runScan: AssumeRole failure marks the scan failed with a short message and no snapshot", async () => {
  const db = openDatabase(":memory:");
  const { deps } = fakeDeps({
    sts: {
      assumeRole: async () => {
        const e = new Error("User is not authorized to perform: sts:AssumeRole");
        e.name = "AccessDenied";
        throw e;
      },
      hostIdentity: async () => ({ account: "1", arn: "x" }),
    },
  });
  db.accounts.upsert({ ...ACCOUNT, status: "active" });
  db.scans.enqueue(ACCOUNT.id, "manual");
  const scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  const done = db.scans.get(scan.id)!;
  assert.equal(done.status, "failed");
  assert.equal(done.error, "AccessDenied: User is not authorized to perform: sts:AssumeRole");
  assert.equal(db.snapshots.latestForAccount(ACCOUNT.id), null);
  db.close();
});

test("runScan: explicit account regions skip region enumeration", async () => {
  const db = openDatabase(":memory:");
  let enumerated = false;
  const { deps, calls } = fakeDeps({
    listRegions: async () => {
      enumerated = true;
      return ["ap-south-1"];
    },
  });
  db.accounts.upsert({ ...ACCOUNT, status: "active", regions: ["us-west-2"] });
  db.scans.enqueue(ACCOUNT.id, "manual");
  const scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  assert.equal(enumerated, false);
  assert.ok(calls.some((c) => c.region === "us-west-2"));
  assert.equal(db.scans.get(scan.id)!.status, "ok");
  db.close();
});

test("runScan: verify trigger activates the account without discovery", async () => {
  const db = openDatabase(":memory:");
  const { deps, calls } = fakeDeps();
  db.accounts.upsert(ACCOUNT); // pending
  db.scans.enqueue(ACCOUNT.id, "verify");
  const scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  assert.equal(db.scans.get(scan.id)!.status, "ok");
  assert.equal(db.accounts.get(ACCOUNT.id)!.status, "active");
  assert.equal(calls.length, 1, "only the identity check");
  assert.equal(db.snapshots.latestForAccount(ACCOUNT.id), null);
  db.close();
});

test("runScan: verify fails when the role lands in a different account", async () => {
  const db = openDatabase(":memory:");
  const { deps } = fakeDeps();
  db.accounts.upsert({ ...ACCOUNT, id: "999999999999" });
  db.scans.enqueue("999999999999", "verify");
  const scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get("999999999999")!, db, deps, silentLogger);
  assert.equal(db.scans.get(scan.id)!.status, "failed");
  assert.match(db.scans.get(scan.id)!.error ?? "", /resolved to account 123456789012/);
  assert.equal(db.accounts.get("999999999999")!.status, "pending");
  db.close();
});

test("runScan: the master credentials are scrubbed after the run", async () => {
  const db = openDatabase(":memory:");
  let issued: AwsCredentials | null = null;
  const { deps } = fakeDeps({
    sts: {
      assumeRole: async (input) => {
        issued = { accessKeyId: "ASIA", secretAccessKey: "s", sessionToken: "t", region: input.region };
        return issued;
      },
      hostIdentity: async () => ({ account: "1", arn: "x" }),
    },
  });
  db.accounts.upsert({ ...ACCOUNT, status: "active" });
  db.scans.enqueue(ACCOUNT.id, "manual");
  const scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  assert.equal(issued!.accessKeyId, "");
  assert.equal(issued!.secretAccessKey, "");
  assert.equal(issued!.sessionToken, "");
  db.close();
});

test("Scheduler.tick: enqueues due active accounts, skips inactive, runs the queue", async () => {
  const db = openDatabase(":memory:");
  const { deps } = fakeDeps();
  db.accounts.upsert({ ...ACCOUNT, status: "active", scheduleCron: "0 * * * *" });
  db.accounts.upsert({ ...ACCOUNT, id: "210987654321", name: "dev", status: "pending" });
  const s = new Scheduler(db, deps, { log: silentLogger });

  const first = await s.tick();
  assert.deepEqual(first, { enqueued: 1, ran: 1 });
  assert.equal(db.scans.listForAccount(ACCOUNT.id)[0]!.status, "ok");
  assert.equal(db.scans.listForAccount("210987654321").length, 0);

  // Same instant again: not due (next hourly run is after the last start).
  const second = await s.tick();
  assert.deepEqual(second, { enqueued: 0, ran: 0 });

  // An hour later: due again.
  deps.now = () => new Date("2026-09-19T13:00:00Z");
  const third = await s.tick();
  assert.deepEqual(third, { enqueued: 1, ran: 1 });
  assert.equal(db.scans.listForAccount(ACCOUNT.id).length, 2);
  s.stop();
  db.close();
});

test("Scheduler.tick: a worker without the lease still drains the queue", async () => {
  const db = openDatabase(":memory:");
  const { deps } = fakeDeps();
  db.accounts.upsert({ ...ACCOUNT, status: "active" });
  db.leases.acquire("scheduler", "someone-else", 60_000);
  db.scans.enqueue(ACCOUNT.id, "manual");
  const s = new Scheduler(db, deps, { log: silentLogger });
  assert.deepEqual(await s.tick(), { enqueued: 0, ran: 1 });
  db.close();
});
