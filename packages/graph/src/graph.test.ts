import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, checkReferentialIntegrity } from "./validate.js";
import { sampleGraph } from "./sample.js";
import { LENSES } from "./schema.js";

test("sample graph passes schema validation", () => {
  // Round-trip through the runtime schema; throws on any mismatch.
  const parsed = parseGraph(sampleGraph);
  assert.equal(parsed.meta.provider, "aws");
  assert.ok(parsed.nodes.length > 0);
  assert.ok(parsed.edges.length > 0);
});

test("sample graph is referentially intact", () => {
  const problems = checkReferentialIntegrity(sampleGraph);
  assert.deepEqual(problems, []);
});

test("sample graph exercises all three lenses", () => {
  const used = new Set(sampleGraph.edges.map((e) => e.lens));
  for (const lens of LENSES) {
    assert.ok(used.has(lens), `expected at least one '${lens}' edge`);
  }
});

test("sample graph carries security findings but never raw secret values", () => {
  assert.ok(sampleGraph.findings.length >= 1);

  // No attribute anywhere should hold a resolved secret value; secrets are only
  // ever represented as markers.
  for (const node of sampleGraph.nodes) {
    const json = JSON.stringify(node.attributes);
    assert.ok(
      !/valueResolved"\s*:\s*true/.test(json),
      `node ${node.id} must not resolve secret values`,
    );
  }
});

test("validation rejects an edge pointing at a missing node", () => {
  const broken = structuredClone(sampleGraph);
  broken.edges.push({
    id: "e-broken",
    source: broken.nodes[0]!.id,
    target: "arn:aws:does-not-exist",
    relationship: "can-assume",
    lens: "iam",
    attributes: {},
  });
  const problems = checkReferentialIntegrity(broken);
  assert.ok(problems.some((p) => p.includes("unknown target")));
});

test("validation flags a self-loop edge", () => {
  const broken = structuredClone(sampleGraph);
  const nodeId = broken.nodes[0]!.id;
  broken.edges.push({
    id: "e-self",
    source: nodeId,
    target: nodeId,
    relationship: "allows-ingress",
    lens: "network",
    attributes: {},
  });
  const problems = checkReferentialIntegrity(broken);
  assert.ok(problems.some((p) => p.includes("self-loop")));
});

test("validation flags a duplicate finding id", () => {
  const broken = structuredClone(sampleGraph);
  const dup = structuredClone(broken.findings[0]!);
  broken.findings.push(dup);
  const problems = checkReferentialIntegrity(broken);
  assert.ok(problems.some((p) => p.includes("duplicate finding id")));
});
