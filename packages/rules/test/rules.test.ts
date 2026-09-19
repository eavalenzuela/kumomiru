import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, type Graph, type CloudNode } from "@kumomiru/graph";
import {
  defaultRegistry,
  evaluate,
  controlStatuses,
  findingId,
  CATALOGUES,
  RuleRegistry,
} from "../src/index.js";

const ACCOUNT = "123456789012";
const ALL_CAPS = [
  "ec2:vpc", "ec2:subnet", "ec2:internet-gateway", "ec2:security-group", "ec2:instance",
  "rds:db-instance", "lambda:function", "secretsmanager:secret", "iam:role", "iam:user",
];

function node(id: string, type: string, attributes: Record<string, unknown> = {}, parent?: string): CloudNode {
  return { id, type, name: id, account: ACCOUNT, region: "us-east-1", ...(parent ? { parent } : {}), tags: {}, attributes };
}

/** A small graph with one offender and one clean resource per rule. */
function graph(): Graph {
  const nodes: CloudNode[] = [
    node("acct", "aws::account"),
    node("region", "aws::region", {}, "acct"),
    node("sg-ssh", "aws::ec2::security-group", {
      ingress: [{ fromPort: 22, toPort: 22, protocol: "tcp", cidrs: ["0.0.0.0/0"], sourceGroupIds: [] }],
    }, "region"),
    node("sg-all", "aws::ec2::security-group", {
      ingress: [{ protocol: "-1", cidrs: ["::/0"], sourceGroupIds: [] }],
    }, "region"),
    node("sg-web", "aws::ec2::security-group", {
      ingress: [
        { fromPort: 443, toPort: 443, protocol: "tcp", cidrs: ["0.0.0.0/0"], sourceGroupIds: [] },
        { fromPort: 5432, toPort: 5432, protocol: "tcp", cidrs: [], sourceGroupIds: ["sg-app"] },
      ],
    }, "region"),
    node("sg-corp", "aws::ec2::security-group", {
      ingress: [{ fromPort: 22, toPort: 22, protocol: "tcp", cidrs: ["198.51.100.0/24"], sourceGroupIds: [] }],
    }, "region"),
    node("subnet-pub", "aws::ec2::subnet", { mapPublicIpOnLaunch: true }, "region"),
    node("subnet-priv", "aws::ec2::subnet", { mapPublicIpOnLaunch: false }, "region"),
    node("db-pub", "aws::rds::db-instance", { publiclyAccessible: true }, "region"),
    node("db-priv", "aws::rds::db-instance", { publiclyAccessible: false }, "region"),
    node("arn:aws:iam::123456789012:role/Admin", "aws::iam::role", {}, "acct"),
  ];
  return parseGraph({
    nodes,
    edges: [],
    findings: [
      {
        id: "f-ext-abc",
        severity: "critical",
        kind: "external-can-assume",
        nodeId: "arn:aws:iam::123456789012:role/Admin",
        title: "external principal can assume Admin",
        detail: "trusts 999988887777",
      },
      { id: "f-other", severity: "low", kind: "something-unknown", title: "x", detail: "y" },
    ],
    meta: { generatedAt: "2026-09-19T00:00:00Z", source: "aws-live", provider: "aws" },
  });
}

test("evaluate: fails the offenders, passes the clean resources, deterministic ids", () => {
  const ev = evaluate(graph(), defaultRegistry(), { capabilities: ALL_CAPS });
  const failed = (ruleId: string) =>
    ev.results.filter((r) => r.ruleId === ruleId && r.status === "fail").map((r) => r.resourceId).sort();
  const passed = (ruleId: string) =>
    ev.results.filter((r) => r.ruleId === ruleId && r.status === "pass").map((r) => r.resourceId).sort();

  assert.deepEqual(failed("ec2.sg-unrestricted-ssh"), ["sg-all", "sg-ssh"]);
  assert.deepEqual(passed("ec2.sg-unrestricted-ssh"), ["sg-corp", "sg-web"]);
  assert.deepEqual(failed("ec2.sg-unrestricted-rdp"), ["sg-all"]);
  assert.deepEqual(failed("ec2.sg-unrestricted-high-risk-ports"), ["sg-all", "sg-ssh"]);
  assert.deepEqual(failed("ec2.sg-unrestricted-unauthorized-ports"), ["sg-all", "sg-ssh"]);
  assert.deepEqual(passed("ec2.sg-unrestricted-unauthorized-ports"), ["sg-corp", "sg-web"]);
  assert.deepEqual(failed("ec2.subnet-auto-assign-public-ip"), ["subnet-pub"]);
  assert.deepEqual(failed("rds.instance-publicly-accessible"), ["db-pub"]);
  assert.deepEqual(ev.notAssessedRules, []);

  const ssh = ev.findings.find((f) => f.ruleId === "ec2.sg-unrestricted-ssh" && f.nodeId === "sg-ssh")!;
  assert.equal(ssh.id, findingId("ec2.sg-unrestricted-ssh", "sg-ssh"));
  assert.equal(ssh.severity, "high");
  assert.equal(ssh.source, "native");
  assert.equal(ssh.resourceType, "aws::ec2::security-group");
  assert.deepEqual(ssh.controls, [{ framework: "fsbp", id: "EC2.13" }, { framework: "nist-csf-2", id: "PR.IR-01" }]);
  assert.ok(ssh.remediation?.cli?.includes("revoke-security-group-ingress"));
  assert.match(ssh.detail, /port 22 open/);

  const hr = ev.findings.find((f) => f.ruleId === "ec2.sg-unrestricted-high-risk-ports" && f.nodeId === "sg-all")!;
  assert.ok((hr.evidence?.["ports"] as number[]).includes(3306));

  // Same input → same ids.
  const again = evaluate(graph(), defaultRegistry(), { capabilities: ALL_CAPS });
  assert.deepEqual(again.findings.map((f) => f.id), ev.findings.map((f) => f.id));
});

test("evaluate: adopts adapter findings, leaves unknown kinds untouched", () => {
  const ev = evaluate(graph(), defaultRegistry(), { capabilities: ALL_CAPS });
  const ext = ev.findings.find((f) => f.id === "f-ext-abc")!;
  assert.equal(ext.ruleId, "kumomiru.external-can-assume");
  assert.equal(ext.resourceType, "aws::iam::role");
  assert.ok(ext.remediation?.text.includes("ExternalId"));
  assert.deepEqual(ext.controls, [{ framework: "nist-csf-2", id: "PR.AA-05" }]);
  const other = ev.findings.find((f) => f.id === "f-other")!;
  assert.equal(other.ruleId, undefined);
});

test("evaluate: a missing capability yields not-assessed, never pass", () => {
  const caps = ALL_CAPS.filter((c) => c !== "ec2:security-group");
  const ev = evaluate(graph(), defaultRegistry(), { capabilities: caps });
  const sgResults = ev.results.filter((r) => r.resourceType === "aws::ec2::security-group");
  assert.ok(sgResults.length > 0);
  assert.ok(sgResults.every((r) => r.status === "not-assessed"));
  assert.ok(ev.notAssessedRules.includes("ec2.sg-unrestricted-ssh"));
  assert.ok(!ev.findings.some((f) => f.ruleId === "ec2.sg-unrestricted-ssh"));
  // Unaffected rules still run.
  assert.ok(ev.results.some((r) => r.ruleId === "rds.instance-publicly-accessible" && r.status === "fail"));
});

test("controlStatuses: rolls results up per control for both frameworks", () => {
  const reg = defaultRegistry();
  const ev = evaluate(graph(), reg, { capabilities: ALL_CAPS });
  const fsbp = controlStatuses("fsbp", ev.results, reg);
  const byId = new Map(fsbp.map((c) => [c.controlId, c]));
  assert.equal(byId.get("EC2.13")!.status, "fail");
  assert.deepEqual(byId.get("EC2.13")!.failingResourceIds.sort(), ["sg-all", "sg-ssh"]);
  assert.equal(byId.get("EC2.13")!.pass, 2);
  assert.equal(byId.get("RDS.2")!.status, "fail");
  assert.equal(byId.get("S3.1")!.status, "not-assessed", "unmapped control is visible as a gap");
  assert.deepEqual(byId.get("S3.1")!.ruleIds, []);

  const nist = controlStatuses("nist-csf-2", ev.results, reg);
  const ir = nist.find((c) => c.controlId === "PR.IR-01")!;
  assert.equal(ir.status, "fail");
  assert.ok(ir.ruleIds.length >= 5);

  // A clean graph passes the mapped controls.
  const clean = evaluate({ ...graph(), findings: [], nodes: graph().nodes.filter((n) => !["sg-ssh", "sg-all", "subnet-pub", "db-pub"].includes(n.id)) }, reg, { capabilities: ALL_CAPS });
  const cleanFsbp = new Map(controlStatuses("fsbp", clean.results, reg).map((c) => [c.controlId, c]));
  assert.equal(cleanFsbp.get("EC2.13")!.status, "pass");
  assert.equal(cleanFsbp.get("RDS.2")!.status, "pass");
});

test("registry: rejects duplicate ids and replaced-but-still-registered ids; every control id exists", () => {
  const reg = defaultRegistry();
  assert.throws(() => reg.register(reg.list()[0]!), /duplicate/);
  const r2 = new RuleRegistry().register({ ...reg.list()[0]!, id: "old.rule" });
  assert.throws(() => r2.register({ ...reg.list()[1]!, id: "new.rule", replaces: ["old.rule"] }), /replaces/);

  const known = new Map(CATALOGUES.map((c) => [c.framework, new Set(c.controls.map((x) => x.id))]));
  for (const rule of reg.list()) {
    for (const c of rule.controls) {
      assert.ok(known.get(c.framework)?.has(c.id), `${rule.id} → ${c.framework}:${c.id} not in catalogue`);
    }
    assert.match(rule.id, /^[a-z0-9]+\.[a-z0-9-]+$/, rule.id);
    assert.ok(rule.remediation.text.length > 20, rule.id);
  }
});
