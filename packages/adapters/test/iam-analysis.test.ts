import { test } from "node:test";
import assert from "node:assert/strict";

import {
  analyzeAssumeRole,
  evaluatePolicy,
  type AnalyzedPrincipal,
  type PolicyStatement,
} from "../src/index.js";

const ACCOUNT = "123456789012";
const EXTERNAL = "999988887777";
const acctNode = `aws::account::${ACCOUNT}`;
const roleArn = (name: string) => `arn:aws:iam::${ACCOUNT}:role/${name}`;
const userArn = (name: string) => `arn:aws:iam::${ACCOUNT}:user/${name}`;

/** Identity statement allowing sts:AssumeRole on a specific resource. */
function allowAssume(
  resource: string,
  conditionKeys?: string[],
): PolicyStatement {
  return {
    effect: "Allow",
    actions: ["sts:AssumeRole"],
    resources: [resource],
    ...(conditionKeys ? { conditionKeys } : {}),
  };
}

// --- policy evaluator --------------------------------------------------------

test("evaluate: explicit deny beats allow regardless of order", () => {
  const stmts: PolicyStatement[] = [
    allowAssume("*"),
    { effect: "Deny", actions: ["sts:*"], resources: ["*"] },
  ];
  assert.equal(
    evaluatePolicy(stmts, "sts:AssumeRole", roleArn("x")).decision,
    "deny",
  );
});

test("evaluate: wildcards expand for action and resource", () => {
  const stmts = [
    { effect: "Allow" as const, actions: ["sts:*"], resources: ["arn:aws:iam::*:role/app-*"] },
  ];
  assert.equal(
    evaluatePolicy(stmts, "sts:AssumeRole", roleArn("app-worker")).decision,
    "allow",
  );
  assert.equal(
    evaluatePolicy(stmts, "sts:AssumeRole", roleArn("other")).decision,
    "implicit-deny",
  );
});

test("evaluate: a matched allow carries its condition keys", () => {
  const res = evaluatePolicy(
    [allowAssume(roleArn("x"), ["aws:MultiFactorAuthPresent"])],
    "sts:AssumeRole",
    roleArn("x"),
  );
  assert.equal(res.decision, "allow");
  assert.deepEqual(res.conditionKeys, ["aws:MultiFactorAuthPresent"]);
});

test("evaluate: no matching statement is implicit deny", () => {
  assert.equal(
    evaluatePolicy([allowAssume(roleArn("a"))], "sts:AssumeRole", roleArn("b"))
      .decision,
    "implicit-deny",
  );
});

// --- assume-role analysis pass ----------------------------------------------

test("internal can-assume requires BOTH trust and identity", () => {
  const target = roleArn("target");
  const allowed = roleArn("allowed");
  const trustedButNoIdentity = roleArn("trusted-no-identity");

  const principals: AnalyzedPrincipal[] = [
    {
      id: target,
      account: ACCOUNT,
      kind: "role",
      identity: [],
      // trust both roles via the account root (whole-account trust).
      trust: [{ principalValue: `arn:aws:iam::${ACCOUNT}:root`, type: "aws" }],
    },
    {
      id: allowed,
      account: ACCOUNT,
      kind: "role",
      identity: [allowAssume(target)], // identity ALSO allows -> edge
    },
    {
      id: trustedButNoIdentity,
      account: ACCOUNT,
      kind: "role",
      identity: [], // trusted by root but identity does NOT allow -> no edge
    },
  ];

  const { edges } = analyzeAssumeRole(principals, ACCOUNT, acctNode);
  const sources = edges
    .filter((e) => e.target === target)
    .map((e) => e.source);
  assert.deepEqual(sources, [allowed]);
});

test("explicit identity deny suppresses an otherwise-trusted edge", () => {
  const target = roleArn("target");
  const blocked = roleArn("blocked");
  const principals: AnalyzedPrincipal[] = [
    {
      id: target,
      account: ACCOUNT,
      kind: "role",
      identity: [],
      trust: [{ principalValue: blocked, type: "aws" }],
    },
    {
      id: blocked,
      account: ACCOUNT,
      kind: "role",
      identity: [
        allowAssume(target),
        { effect: "Deny", actions: ["sts:AssumeRole"], resources: [target] },
      ],
    },
  ];
  const { edges } = analyzeAssumeRole(principals, ACCOUNT, acctNode);
  assert.equal(edges.length, 0);
});

test("a user can be an assume-role source", () => {
  const target = roleArn("deploy");
  const u = userArn("ci");
  const principals: AnalyzedPrincipal[] = [
    {
      id: target,
      account: ACCOUNT,
      kind: "role",
      identity: [],
      trust: [{ principalValue: u, type: "aws" }],
    },
    { id: u, account: ACCOUNT, kind: "user", identity: [allowAssume(target)] },
  ];
  const { edges } = analyzeAssumeRole(principals, ACCOUNT, acctNode);
  assert.equal(edges.length, 1);
  assert.equal(edges[0]!.source, u);
  assert.equal(edges[0]!.attributes["identityConfirmed"], true);
});

test("external trust is an exposure: edge + node + critical finding", () => {
  const admin = roleArn("Admin");
  const principals: AnalyzedPrincipal[] = [
    {
      id: admin,
      account: ACCOUNT,
      kind: "role",
      identity: [],
      trust: [
        { principalValue: `arn:aws:iam::${EXTERNAL}:root`, type: "aws" },
      ],
    },
  ];
  const { nodes, edges, findings } = analyzeAssumeRole(
    principals,
    ACCOUNT,
    acctNode,
  );
  const edge = edges.find((e) => e.target === admin);
  assert.ok(edge, "expected an external can-assume edge");
  assert.equal(edge!.attributes["external"], true);
  assert.equal(edge!.attributes["identityUnverified"], true);
  assert.equal(edge!.lens, "iam");
  assert.ok(
    nodes.some((n) => n.id === edge!.source && n.parent === acctNode),
    "expected a synthesized external-principal node parented to the account",
  );
  const f = findings.find((f) => f.kind === "external-can-assume");
  assert.ok(f);
  assert.equal(f!.severity, "critical");
});

test("a condition on external trust downgrades to high + marks conditional", () => {
  const admin = roleArn("Admin");
  const principals: AnalyzedPrincipal[] = [
    {
      id: admin,
      account: ACCOUNT,
      kind: "role",
      identity: [],
      trust: [
        {
          principalValue: `arn:aws:iam::${EXTERNAL}:root`,
          type: "aws",
          conditionKeys: ["sts:ExternalId"],
        },
      ],
    },
  ];
  const { edges, findings } = analyzeAssumeRole(principals, ACCOUNT, acctNode);
  const edge = edges.find((e) => e.target === admin)!;
  assert.equal(edge.attributes["conditional"], true);
  assert.deepEqual(edge.attributes["conditions"], ["sts:ExternalId"]);
  assert.equal(
    findings.find((f) => f.kind === "external-can-assume")!.severity,
    "high",
  );
});

test("service trust does not produce an assume edge", () => {
  const role = roleArn("web-instance-role");
  const principals: AnalyzedPrincipal[] = [
    {
      id: role,
      account: ACCOUNT,
      kind: "role",
      identity: [],
      trust: [{ principalValue: "ec2.amazonaws.com", type: "service" }],
    },
  ];
  const { edges, findings } = analyzeAssumeRole(principals, ACCOUNT, acctNode);
  assert.equal(edges.length, 0);
  assert.equal(findings.length, 0);
});
