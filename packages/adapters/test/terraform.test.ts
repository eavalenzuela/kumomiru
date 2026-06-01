import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { parseGraph, checkReferentialIntegrity } from "@kumomiru/graph";
import { terraformAdapter } from "../src/index.js";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/simple.tfstate.json", import.meta.url)),
    "utf8",
  ),
);

test("produces a schema-valid, referentially-intact graph", () => {
  const graph = terraformAdapter.toGraph(fixture);
  parseGraph(graph); // throws on schema mismatch
  assert.deepEqual(checkReferentialIntegrity(graph), []);
  assert.equal(graph.meta.source, "terraform-state");
});

test("maps managed resources, skips data sources", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const types = graph.nodes.map((n) => n.type);
  assert.ok(types.includes("aws::ec2::vpc"));
  assert.ok(types.includes("aws::ec2::instance"));
  assert.ok(types.includes("aws::iam::role"));
  // the aws_caller_identity data source must not appear
  assert.ok(!graph.nodes.some((n) => n.name === "current"));
});

test("synthesizes account and region container nodes", () => {
  const graph = terraformAdapter.toGraph(fixture);
  assert.ok(graph.nodes.some((n) => n.type === "aws::account"));
  assert.ok(graph.nodes.some((n) => n.type === "aws::region"));
});

test("builds the containment chain account -> region -> vpc -> subnet -> instance", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const inst = graph.nodes.find((n) => n.type === "aws::ec2::instance")!;
  const subnet = byId.get(inst.parent!)!;
  assert.equal(subnet.type, "aws::ec2::subnet");
  const vpc = byId.get(subnet.parent!)!;
  assert.equal(vpc.type, "aws::ec2::vpc");
  const region = byId.get(vpc.parent!)!;
  assert.equal(region.type, "aws::region");
  const account = byId.get(region.parent!)!;
  assert.equal(account.type, "aws::account");
});

test("IAM role is parented to the account, not a region", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const role = graph.nodes.find((n) => n.type === "aws::iam::role")!;
  assert.equal(byId.get(role.parent!)!.type, "aws::account");
});

test("derives network edges: IGW attachment and SG membership", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const rels = graph.edges.map((e) => e.relationship);
  assert.ok(rels.includes("attached-to"));
  assert.ok(rels.includes("protects"));
  assert.ok(graph.edges.every((e) => e.lens === "network"));
});
