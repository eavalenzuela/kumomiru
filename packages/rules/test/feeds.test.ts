import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, type CloudNode, type Graph } from "@kumomiru/graph";
import { defaultRegistry, evaluate, controlStatuses, findingId } from "../src/index.js";

const ACCOUNT = "123456789012";
const CAPS = ["ec2:security-group", "rds:db-instance", "ec2:subnet"];

function node(id: string, type: string, attributes: Record<string, unknown> = {}): CloudNode {
  return { id, type, name: id, account: ACCOUNT, region: "us-east-1", tags: {}, attributes };
}

function graph(withHub: boolean): Graph {
  return parseGraph({
    nodes: [
      node("sg-ssh", "aws::ec2::security-group", { ingress: [{ fromPort: 22, toPort: 22, protocol: "tcp", cidrs: ["0.0.0.0/0"], sourceGroupIds: [] }] }),
      node("sg-rdp", "aws::ec2::security-group", { ingress: [{ fromPort: 3389, toPort: 3389, protocol: "tcp", cidrs: ["0.0.0.0/0"], sourceGroupIds: [] }] }),
      node("db", "aws::rds::db-instance", { publiclyAccessible: true }),
    ],
    edges: [],
    findings: withHub
      ? [
          // Security Hub agrees sg-ssh fails EC2.13 ...
          { id: "f-sh-1", severity: "high", kind: "securityhub-ec2.13", nodeId: "sg-ssh", title: "SH: port 22 open", detail: "d", ruleId: "securityhub.EC2.13", source: "securityhub", controls: [{ framework: "fsbp", id: "EC2.13" }], resourceType: "aws::ec2::security-group", externalId: "arn:sh:1", evidence: { complianceStatus: "FAILED", resourceIds: ["sg-ssh"] } },
          // ... and reports IAM.6 failing on the account (no native rule exists for it).
          { id: "f-sh-2", severity: "critical", kind: "securityhub-iam.6", title: "SH: root hardware MFA", detail: "d", ruleId: "securityhub.IAM.6", source: "securityhub", controls: [{ framework: "fsbp", id: "IAM.6" }], evidence: { complianceStatus: "FAILED", resourceIds: ["AWS::::Account:123456789012"] } },
          // A GuardDuty finding routed through Security Hub: no control.
          { id: "f-sh-3", severity: "medium", kind: "securityhub-guardduty", title: "brute force", detail: "d", ruleId: "securityhub.guardduty", source: "securityhub", controls: [] },
        ]
      : [],
    // Security Hub reported EC2.13 (failed above), EC2.14 (all passed), IAM.6 (failed). RDS.2 was NOT reported.
    meta: { generatedAt: "2026-09-19T00:00:00Z", source: "aws-live", provider: "aws", ...(withHub ? { feeds: ["securityhub"], securityHubControls: ["EC2.13", "EC2.14", "IAM.6"] } : {}) },
  });
}

test("without Security Hub: native rules decide everything", () => {
  const reg = defaultRegistry();
  const ev = evaluate(graph(false), reg, { capabilities: CAPS });
  assert.ok(ev.findings.some((f) => f.ruleId === "ec2.sg-unrestricted-ssh"));
  assert.deepEqual(ev.supersededFindings, []);
  const byId = new Map(controlStatuses("fsbp", ev.results, reg).map((c) => [c.controlId, c]));
  assert.equal(byId.get("EC2.13")!.status, "fail");
  assert.equal(byId.get("EC2.13")!.source, "native");
  assert.equal(byId.get("IAM.6")!.status, "not-assessed");
  assert.equal(byId.get("RDS.2")!.status, "fail");
});

test("with Security Hub: feed rows supersede per control, native findings on the same resource are dropped, RDS.2 stays native", () => {
  const reg = defaultRegistry();
  const ev = evaluate(graph(true), reg, { capabilities: CAPS });

  // Native ssh finding for sg-ssh is superseded by the feed's; sg-rdp's native EC2.14 finding is NOT
  // (Security Hub said EC2.14 passed everywhere, so we keep native as a second opinion in findings).
  assert.deepEqual(ev.supersededFindings, [findingId("ec2.sg-unrestricted-ssh", "sg-ssh")]);
  assert.ok(!ev.findings.some((f) => f.id === findingId("ec2.sg-unrestricted-ssh", "sg-ssh")));
  assert.ok(ev.findings.some((f) => f.id === "f-sh-1"));
  assert.ok(ev.findings.some((f) => f.ruleId === "ec2.sg-unrestricted-rdp" && f.nodeId === "sg-rdp"));

  // Feed rows: EC2.13 fail on sg-ssh, IAM.6 fail on the account id, EC2.14 synthetic pass.
  assert.ok(ev.results.some((r) => r.ruleId === "securityhub.EC2.13" && r.resourceId === "sg-ssh" && r.status === "fail"));
  assert.ok(ev.results.some((r) => r.ruleId === "securityhub.IAM.6" && r.status === "fail"));
  assert.ok(ev.results.some((r) => r.ruleId === "securityhub.EC2.14" && r.status === "pass" && r.resourceType === "aws::securityhub::control"));
  // Native rows are still produced (stored for history), but do not decide covered controls.
  assert.ok(ev.results.some((r) => r.ruleId === "ec2.sg-unrestricted-rdp" && r.resourceId === "sg-rdp" && r.status === "fail"));

  const byId = new Map(controlStatuses("fsbp", ev.results, reg).map((c) => [c.controlId, c]));
  assert.equal(byId.get("EC2.13")!.source, "securityhub");
  assert.equal(byId.get("EC2.13")!.status, "fail");
  assert.deepEqual(byId.get("EC2.13")!.failingResourceIds, ["sg-ssh"]);
  assert.equal(byId.get("EC2.14")!.source, "securityhub");
  assert.equal(byId.get("EC2.14")!.status, "pass", "AWS says EC2.14 passes; native's sg-rdp fail is superseded in the roll-up");
  assert.deepEqual(byId.get("EC2.14")!.failingResourceIds, []);
  assert.equal(byId.get("IAM.6")!.source, "securityhub");
  assert.equal(byId.get("IAM.6")!.status, "fail", "a control with no native rule is now assessed via the feed");
  assert.equal(byId.get("RDS.2")!.source, "native");
  assert.equal(byId.get("RDS.2")!.status, "fail", "not reported by Security Hub → native fallback");
  // NIST roll-up is unaffected by feed rows (no NIST mapping on feed findings).
  const nist = controlStatuses("nist-csf-2", ev.results, reg).find((c) => c.controlId === "PR.IR-01")!;
  assert.equal(nist.source, "native");
});
