import { test } from "node:test";
import assert from "node:assert/strict";

import { openDatabase } from "@kumomiru/db";
import type { AwsCredentials } from "@kumomiru/adapters";
import { Scheduler, runScan, silentLogger, syncRuleMetadata, type WorkerDeps } from "../src/index.js";
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

test("runScan: rules run on the snapshot; lifecycle opens, holds, and resolves across scans", async () => {
  const db = openDatabase(":memory:");
  db.accounts.upsert({ ...ACCOUNT, status: "active", regions: ["us-east-1"] });

  // Scan 1: the fake SG allows 22 from 0.0.0.0/0 → sg-open-ssh + high-risk + unauthorized-port findings.
  const { deps } = fakeDeps();
  db.scans.enqueue(ACCOUNT.id, "manual");
  let scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  let done = db.scans.get(scan.id)!;
  assert.equal(done.status, "ok", done.error ?? "");
  const snap1 = db.snapshots.latestForAccount(ACCOUNT.id)!;
  const g1 = db.snapshots.getGraph(snap1.id)!;
  const ssh = g1.findings.find((f) => f.ruleId === "ec2.sg-unrestricted-ssh");
  assert.ok(ssh, "rule finding is stored in the snapshot graph");
  assert.equal(ssh!.nodeId, "arn:aws:ec2:us-east-1:123456789012:security-group/sg-us-east-1");
  const ext = g1.findings.find((f) => f.kind === "external-can-assume");
  assert.equal(ext!.ruleId, "kumomiru.external-can-assume", "adapter finding adopted");
  assert.ok(db.ruleResults.forSnapshot(snap1.id).some((r) => r.ruleId === "ec2.sg-unrestricted-ssh" && r.status === "fail"));
  assert.equal(done.stats?.["findingsOpened"], g1.findings.length);
  assert.equal(db.findings.get(ssh!.id)!.status, "open");
  const diff1 = db.diffs.get(snap1.id)!;
  assert.equal(diff1.prevSnapshotId, null);
  assert.equal(diff1.nodesAdded.length, g1.nodes.length);

  // Scan 2: same environment, one hour later → nothing new, nothing resolved.
  deps.now = () => new Date("2026-09-19T13:00:00Z");
  db.scans.enqueue(ACCOUNT.id, "manual");
  scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  done = db.scans.get(scan.id)!;
  assert.equal(done.stats?.["findingsOpened"], 0);
  assert.equal(done.stats?.["findingsResolved"], 0);
  assert.equal(done.stats?.["nodesChanged"], 0);
  const f2 = db.findings.get(ssh!.id)!;
  assert.equal(f2.firstSeenAt, "2026-09-19T12:00:00.000Z");
  assert.equal(f2.lastSeenAt, "2026-09-19T13:00:00.000Z");

  // Scan 3: the SG is fixed (no public rule) → the SSH finding resolves.
  const fixed = fakeClientFactory();
  deps.makeClient = (creds) => {
    const c = fixed.factory(creds);
    return {
      ...c,
      securityGroups: async () => [
        { groupId: `sg-${creds.region}`, vpcId: `vpc-${creds.region}`, ingress: [], tags: {} },
      ],
    };
  };
  deps.now = () => new Date("2026-09-19T14:00:00Z");
  db.scans.enqueue(ACCOUNT.id, "manual");
  scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  done = db.scans.get(scan.id)!;
  assert.ok((done.stats?.["findingsResolved"] as number) >= 1);
  const f3 = db.findings.get(ssh!.id)!;
  assert.equal(f3.status, "resolved");
  assert.equal(f3.resolvedAt, "2026-09-19T14:00:00.000Z");
  const snap3 = db.snapshots.latestForAccount(ACCOUNT.id)!;
  const diff3 = db.diffs.get(snap3.id)!;
  assert.equal(diff3.prevSnapshotId, db.snapshots.listForAccount(ACCOUNT.id)[1]!.id);
  assert.ok(diff3.findingsResolved.some((f) => f.id === ssh!.id));
  assert.ok(diff3.nodesChanged.some((n) => n.changedKeys.includes("attributes.ingress")));
  db.close();
});

test("runScan: a suppression in force makes a new finding start suppressed", async () => {
  const db = openDatabase(":memory:");
  db.accounts.upsert({ ...ACCOUNT, status: "active", regions: ["us-east-1"] });
  db.suppressions.create({ ruleId: "ec2.sg-unrestricted-ssh", resourcePattern: "*", reason: "known bastion" });
  const { deps } = fakeDeps();
  db.scans.enqueue(ACCOUNT.id, "manual");
  const scan = db.scans.claimNext("w-test")!;
  await runScan(scan, db.accounts.get(ACCOUNT.id)!, db, deps, silentLogger);
  const ssh = db.findings.list({ ruleId: "ec2.sg-unrestricted-ssh" })[0]!;
  assert.equal(ssh.status, "suppressed");
  assert.equal(db.scans.get(scan.id)!.stats?.["findingsSuppressed"], 1);
  db.close();
});

test("syncRuleMetadata mirrors rules and controls into the database", async () => {
  const db = openDatabase(":memory:");
  const { defaultRegistry } = await import("@kumomiru/rules");
  syncRuleMetadata(db, defaultRegistry());
  assert.ok(db.metadata.listRules().some((r) => r.id === "ec2.sg-unrestricted-ssh"));
  assert.ok(db.metadata.listControls("fsbp").some((c) => c.id === "EC2.13"));
  assert.ok(db.metadata.listControls("nist-csf-2").some((c) => c.id === "PR.IR-01"));
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
  // The db must share the injected clock: scan.startedAt comes from the db's
  // clock and isDue compares it against deps.now.
  const { deps } = fakeDeps();
  const db = openDatabase(":memory:", { now: () => deps.now() });
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
