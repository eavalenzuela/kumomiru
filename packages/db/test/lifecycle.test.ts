import { test } from "node:test";
import assert from "node:assert/strict";

import type { Finding } from "@kumomiru/graph";
import { sampleGraph } from "@kumomiru/graph";
import { openDatabase } from "../src/index.js";

const ACCOUNT = { id: "123456789012", name: "prod", roleArn: "arn:aws:iam::123456789012:role/R" };

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id, severity: "high", kind: "sg-open-ssh", nodeId: `sg-${id}`, title: "t", detail: "d",
    ruleId: "ec2.sg-unrestricted-ssh", source: "native",
    controls: [{ framework: "fsbp", id: "EC2.13" }], resourceType: "aws::ec2::security-group",
    ...over,
  };
}

function setup() {
  const db = openDatabase(":memory:");
  db.accounts.upsert(ACCOUNT);
  const scan = db.scans.enqueue(ACCOUNT.id, "manual");
  const snap = (t: string) => db.snapshots.insert({ scanId: scan.id, accountId: ACCOUNT.id, graph: { ...sampleGraph, meta: { ...sampleGraph.meta, generatedAt: t } } });
  return { db, snap };
}

test("reconcile: open → unchanged → resolved → reopened, with timestamps", () => {
  const { db, snap } = setup();
  const s1 = snap("2026-09-19T01:00:00Z");
  let r = db.findings.reconcile({ accountId: ACCOUNT.id, snapshotId: s1.id, observedAt: "2026-09-19T01:00:00Z", findings: [finding("a"), finding("b")], suppressions: [] });
  assert.deepEqual(r.opened.sort(), ["a", "b"]);
  assert.equal(db.findings.get("a")!.status, "open");
  assert.equal(db.findings.get("a")!.firstSeenAt, "2026-09-19T01:00:00Z");

  const s2 = snap("2026-09-19T02:00:00Z");
  r = db.findings.reconcile({ accountId: ACCOUNT.id, snapshotId: s2.id, observedAt: "2026-09-19T02:00:00Z", findings: [finding("a", { detail: "d2" })], suppressions: [] });
  assert.equal(r.unchanged, 1);
  assert.deepEqual(r.resolved, ["b"]);
  const a = db.findings.get("a")!;
  assert.equal(a.detail, "d2");
  assert.equal(a.firstSeenAt, "2026-09-19T01:00:00Z");
  assert.equal(a.lastSeenAt, "2026-09-19T02:00:00Z");
  assert.equal(a.lastSnapshotId, s2.id);
  const b = db.findings.get("b")!;
  assert.equal(b.status, "resolved");
  assert.equal(b.resolvedAt, "2026-09-19T02:00:00Z");

  const s3 = snap("2026-09-19T03:00:00Z");
  r = db.findings.reconcile({ accountId: ACCOUNT.id, snapshotId: s3.id, observedAt: "2026-09-19T03:00:00Z", findings: [finding("a"), finding("b")], suppressions: [] });
  assert.deepEqual(r.reopened, ["b"]);
  assert.equal(db.findings.get("b")!.status, "open");
  assert.equal(db.findings.get("b")!.resolvedAt, null);
  assert.equal(db.findings.get("b")!.firstSeenAt, "2026-09-19T01:00:00Z", "first seen is preserved across reopen");

  assert.deepEqual(db.findings.openCounts(ACCOUNT.id), { info: 0, low: 0, medium: 0, high: 2, critical: 0 });
  assert.equal(db.findings.list({ accountId: ACCOUNT.id, status: "open" }).length, 2);
  assert.equal(db.findings.list({ control: { framework: "fsbp", id: "EC2.13" } }).length, 2);
  assert.equal(db.findings.list({ ruleId: "nope" }).length, 0);
  db.close();
});

test("suppressions: exact, glob, account scope, expiry, revoke; applied at reconcile and on change", () => {
  const { db, snap } = setup();
  const exact = db.suppressions.create({ ruleId: "ec2.sg-unrestricted-ssh", resourcePattern: "sg-a", reason: "bastion" });
  const glob = db.suppressions.create({ ruleId: "ec2.sg-unrestricted-ssh", resourcePattern: "sg-lab-*", reason: "lab", accountId: "999999999999" });
  const expired = db.suppressions.create({ ruleId: "ec2.sg-unrestricted-ssh", resourcePattern: "sg-c", reason: "old", expiresAt: "2026-01-01T00:00:00Z" });

  const now = "2026-09-19T01:00:00Z";
  const active = db.suppressions.activeFor(ACCOUNT.id, now);
  assert.deepEqual(active.map((s) => s.id).sort(), [exact.id].sort(), "other-account and expired suppressions excluded");
  assert.equal(db.suppressions.list().length, 2, "unscoped list includes the other account's glob");
  assert.equal(db.suppressions.list({ includeInactive: true }).length, 3);
  void glob; void expired;

  const s1 = snap(now);
  const r = db.findings.reconcile({
    accountId: ACCOUNT.id, snapshotId: s1.id, observedAt: now,
    findings: [finding("a"), finding("c"), finding("lab-1", { nodeId: "sg-lab-1" })],
    suppressions: active,
  });
  assert.deepEqual(r.suppressed, ["a"]);
  assert.deepEqual(r.opened.sort(), ["c", "lab-1"]);
  assert.equal(db.findings.get("a")!.suppressionId, exact.id);
  assert.deepEqual(db.findings.openCounts(ACCOUNT.id), { info: 0, low: 0, medium: 0, high: 2, critical: 0 });

  // Revoking lifts the suppression on the next apply.
  assert.ok(db.suppressions.revoke(exact.id));
  db.findings.applySuppressions(db.suppressions.list(), now);
  assert.equal(db.findings.get("a")!.status, "open");
  assert.equal(db.findings.get("a")!.suppressionId, null);

  // A new global glob suppression applies immediately.
  const g = db.suppressions.create({ ruleId: "ec2.sg-unrestricted-ssh", resourcePattern: "sg-lab-*", reason: "lab everywhere" });
  db.findings.applySuppressions(db.suppressions.list(), now);
  assert.equal(db.findings.get("lab-1")!.status, "suppressed");
  assert.equal(db.findings.get("lab-1")!.suppressionId, g.id);
  db.close();
});

test("rule results, diffs, and metadata round-trip", () => {
  const { db, snap } = setup();
  const s1 = snap("2026-09-19T01:00:00Z");
  db.ruleResults.replaceForSnapshot(s1.id, [
    { ruleId: "r1", resourceId: "x", resourceType: "t", status: "fail" },
    { ruleId: "r1", resourceId: "y", resourceType: "t", status: "pass" },
  ]);
  db.ruleResults.replaceForSnapshot(s1.id, [{ ruleId: "r1", resourceId: "x", resourceType: "t", status: "pass" }]);
  assert.deepEqual(db.ruleResults.forSnapshot(s1.id), [{ ruleId: "r1", resourceId: "x", resourceType: "t", status: "pass" }]);

  const diff = { prevSnapshotId: null, nextSnapshotId: s1.id, nodesAdded: [{ id: "n", type: "t" }], nodesRemoved: [], nodesChanged: [], edgesAdded: [], edgesRemoved: [], findingsNew: [], findingsResolved: [] };
  db.diffs.set(s1.id, diff);
  assert.deepEqual(db.diffs.get(s1.id), diff);

  db.metadata.syncRules([{ id: "r1", version: 1, title: "T", severity: "high", kind: "k", resourceTypes: ["t"], requires: ["c"], controls: [{ framework: "fsbp", id: "EC2.13" }], remediation: { text: "fix" } }]);
  db.metadata.syncRules([{ id: "r1", version: 2, title: "T2", severity: "high", kind: "k", resourceTypes: ["t"], requires: ["c"], controls: [], remediation: { text: "fix" } }]);
  assert.equal(db.metadata.listRules()[0]!.version, 2);
  db.metadata.syncControls("fsbp", "v1", [{ id: "EC2.13", title: "ssh" }]);
  db.metadata.syncControls("fsbp", "v2", [{ id: "EC2.13", title: "ssh" }, { id: "EC2.14", title: "rdp" }]);
  assert.equal(db.metadata.listControls("fsbp").length, 2);
  assert.equal(db.metadata.listControls("fsbp")[0]!.version, "v2");

  // Deleting the account cascades findings and results.
  db.findings.reconcile({ accountId: ACCOUNT.id, snapshotId: s1.id, observedAt: "2026-09-19T01:00:00Z", findings: [finding("z")], suppressions: [] });
  db.accounts.remove(ACCOUNT.id);
  assert.equal(db.findings.get("z"), null);
  assert.deepEqual(db.ruleResults.forSnapshot(s1.id), []);
  db.close();
});
