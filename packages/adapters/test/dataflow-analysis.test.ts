import { test } from "node:test";
import assert from "node:assert/strict";

import { analyzeDataflow, type DataflowInput } from "../src/index.js";

const app1 = "arn:aws:ec2:us-east-1:111:instance/i-app1";
const app2 = "arn:aws:ec2:us-east-1:111:instance/i-app2";
const db = "arn:aws:ec2:us-east-1:111:instance/i-db";
const secret = "arn:aws:secretsmanager:us-east-1:111:secret:creds-AbC";
const fn = "arn:aws:lambda:us-east-1:111:function:worker";

test("SG-allows expands to instance->instance dataflow edges on the port", () => {
  const input: DataflowInput = {
    members: [
      { id: app1, groupIds: ["sg-app"] },
      { id: db, groupIds: ["sg-db"] },
    ],
    ingress: [{ groupId: "sg-db", sourceGroupIds: ["sg-app"], ports: "5432" }],
    references: [],
  };
  const { edges } = analyzeDataflow(input);
  assert.equal(edges.length, 1);
  assert.equal(edges[0]!.source, app1);
  assert.equal(edges[0]!.target, db);
  assert.equal(edges[0]!.relationship, "talks-to");
  assert.equal(edges[0]!.lens, "dataflow");
  assert.equal(edges[0]!.attributes["ports"], "5432");
});

test("every source member reaches every target member (cross product)", () => {
  const input: DataflowInput = {
    members: [
      { id: app1, groupIds: ["sg-app"] },
      { id: app2, groupIds: ["sg-app"] },
      { id: db, groupIds: ["sg-db"] },
    ],
    ingress: [{ groupId: "sg-db", sourceGroupIds: ["sg-app"], ports: "5432" }],
    references: [],
  };
  const { edges } = analyzeDataflow(input);
  const pairs = edges.map((e) => `${e.source}->${e.target}`).sort();
  assert.deepEqual(pairs, [`${app1}->${db}`, `${app2}->${db}`].sort());
});

test("a self-referential SG rule does not create self-edges", () => {
  const input: DataflowInput = {
    members: [
      { id: app1, groupIds: ["sg-app"] },
      { id: app2, groupIds: ["sg-app"] },
    ],
    ingress: [{ groupId: "sg-app", sourceGroupIds: ["sg-app"], ports: "all" }],
    references: [],
  };
  const { edges } = analyzeDataflow(input);
  // app1<->app2 both directions, but never app1->app1.
  assert.ok(edges.every((e) => e.source !== e.target));
  assert.equal(edges.length, 2);
});

test("ingress from a group with no members yields nothing", () => {
  const input: DataflowInput = {
    members: [{ id: db, groupIds: ["sg-db"] }],
    ingress: [{ groupId: "sg-db", sourceGroupIds: ["sg-empty"], ports: "5432" }],
    references: [],
  };
  assert.equal(analyzeDataflow(input).edges.length, 0);
});

test("duplicate rules on the same pair/port dedupe to one edge", () => {
  const input: DataflowInput = {
    members: [
      { id: app1, groupIds: ["sg-app"] },
      { id: db, groupIds: ["sg-db"] },
    ],
    ingress: [
      { groupId: "sg-db", sourceGroupIds: ["sg-app"], ports: "5432" },
      { groupId: "sg-db", sourceGroupIds: ["sg-app"], ports: "5432" },
    ],
    references: [],
  };
  assert.equal(analyzeDataflow(input).edges.length, 1);
});

test("explicit references become dataflow edges", () => {
  const input: DataflowInput = {
    members: [],
    ingress: [],
    references: [
      { from: fn, to: secret, relationship: "reads-from", via: "lambda-env" },
    ],
  };
  const { edges } = analyzeDataflow(input);
  assert.equal(edges.length, 1);
  assert.equal(edges[0]!.source, fn);
  assert.equal(edges[0]!.target, secret);
  assert.equal(edges[0]!.relationship, "reads-from");
  assert.equal(edges[0]!.attributes["via"], "lambda-env");
});
