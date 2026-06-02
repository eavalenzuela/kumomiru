import { test } from "node:test";
import assert from "node:assert/strict";

import { redactGraph } from "./redact.js";
import { parseGraph, checkReferentialIntegrity } from "./validate.js";
import { sampleGraph } from "./sample.js";

test("redacted graph is still schema-valid and referentially intact", () => {
  const redacted = redactGraph(sampleGraph);
  parseGraph(redacted);
  assert.deepEqual(checkReferentialIntegrity(redacted), []);
});

test("redaction strips IPs and CIDR blocks but keeps structure", () => {
  const redacted = redactGraph(sampleGraph);
  const json = JSON.stringify(redacted);
  // The web server's public IP must not survive.
  assert.ok(!json.includes("203.0.113.10"), "public IP leaked");
  // No CIDR blocks either.
  assert.ok(!json.includes("10.0.0.0/16"), "VPC CIDR leaked");
  assert.ok(!json.includes("10.0.1.0/24"), "subnet CIDR leaked");
  // Topology is preserved: same node and edge counts.
  assert.equal(redacted.nodes.length, sampleGraph.nodes.length);
  assert.equal(redacted.edges.length, sampleGraph.edges.length);
});

test("redaction keeps tag keys but blanks their values", () => {
  const redacted = redactGraph(sampleGraph);
  const vpc = redacted.nodes.find((n) => n.type === "aws::ec2::vpc")!;
  const original = sampleGraph.nodes.find((n) => n.type === "aws::ec2::vpc")!;
  assert.deepEqual(Object.keys(vpc.tags), Object.keys(original.tags));
  assert.ok(Object.keys(vpc.tags).length > 0, "expected the VPC to have tags");
  for (const value of Object.values(vpc.tags)) {
    assert.equal(value, "[redacted]");
  }
});

test("redaction is pure — the input graph is untouched", () => {
  const before = JSON.stringify(sampleGraph);
  redactGraph(sampleGraph);
  assert.equal(JSON.stringify(sampleGraph), before);
});

test("secret markers survive redaction (they hold no value)", () => {
  const redacted = redactGraph(sampleGraph);
  const web = redacted.nodes.find((n) => n.name === "web-server")!;
  assert.deepEqual(web.attributes["userDataSecret"], {
    secretPresent: true,
    kind: "aws-access-key",
  });
});
