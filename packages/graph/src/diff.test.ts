import { test } from "node:test";
import assert from "node:assert/strict";

import { diffSnapshots } from "./diff.js";
import { redactGraph } from "./redact.js";
import { sampleGraph } from "./sample.js";
import { parseGraph } from "./validate.js";
import { FindingRecordSchema, SnapshotDiffSchema } from "./lifecycle.js";

test("diffSnapshots: first snapshot is all additions; identical snapshots diff empty", () => {
  const first = diffSnapshots(null, sampleGraph);
  assert.equal(first.nodesAdded.length, sampleGraph.nodes.length);
  assert.equal(first.findingsNew.length, sampleGraph.findings.length);
  assert.equal(first.prevSnapshotId, null);
  SnapshotDiffSchema.parse(first);

  const same = diffSnapshots(sampleGraph, sampleGraph);
  assert.deepEqual(
    [same.nodesAdded, same.nodesRemoved, same.nodesChanged, same.edgesAdded, same.edgesRemoved, same.findingsNew, same.findingsResolved].map((a) => a.length),
    [0, 0, 0, 0, 0, 0, 0],
  );
});

test("diffSnapshots: detects attribute change, removal, and resolved finding", () => {
  const vpc = sampleGraph.nodes.find((n) => n.type === "aws::ec2::vpc")!;
  const removedNode = sampleGraph.nodes.find((n) => n.type === "aws::lambda::function")!;
  const next = {
    ...sampleGraph,
    nodes: sampleGraph.nodes
      .filter((n) => n.id !== removedNode.id)
      .map((n) => (n.id === vpc.id ? { ...n, attributes: { ...n.attributes, cidrBlock: "10.9.0.0/16" } } : n)),
    // Drop edges that touched the removed node so the graph stays intact.
    edges: sampleGraph.edges.filter((e) => e.source !== removedNode.id && e.target !== removedNode.id),
    findings: sampleGraph.findings.slice(1),
  };
  const d = diffSnapshots(sampleGraph, next);
  assert.deepEqual(d.nodesRemoved.map((n) => n.id), [removedNode.id]);
  assert.deepEqual(d.nodesChanged, [{ id: vpc.id, type: vpc.type, changedKeys: ["attributes.cidrBlock"] }]);
  assert.equal(d.findingsResolved.length, 1);
  assert.equal(d.findingsResolved[0]!.id, sampleGraph.findings[0]!.id);
  assert.ok(d.edgesRemoved.length >= 1);
});

test("finding extensions are optional and survive parse; evidence is redacted", () => {
  const g = parseGraph({
    ...sampleGraph,
    findings: [
      {
        ...sampleGraph.findings[0]!,
        ruleId: "ec2.sg-unrestricted-ssh",
        source: "native",
        controls: [{ framework: "fsbp", id: "EC2.13" }],
        remediation: { text: "Close it", cli: "aws ec2 revoke-security-group-ingress ..." },
        evidence: { cidr: "203.0.113.0/24" },
      },
    ],
  });
  assert.equal(g.findings[0]!.controls?.[0]?.id, "EC2.13");
  const red = redactGraph(g);
  assert.equal(red.findings[0]!.evidence, undefined);
  assert.equal(red.findings[0]!.remediation?.text, "Close it");

  FindingRecordSchema.parse({
    ...g.findings[0]!,
    accountId: "123456789012",
    status: "open",
    firstSeenAt: "2026-09-19T00:00:00Z",
    lastSeenAt: "2026-09-19T00:00:00Z",
    resolvedAt: null,
    lastSnapshotId: "s1",
    suppressionId: null,
  });
});

test("redactGraph keeps SG ingress shape but only public CIDRs", () => {
  const region = sampleGraph.nodes.find((n) => n.type === "aws::region")!;
  const g = {
    ...sampleGraph,
    nodes: [
      ...sampleGraph.nodes,
      {
        id: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-test",
        type: "aws::ec2::security-group",
        name: "test-sg",
        account: region.account,
        region: region.region,
        parent: region.id,
        tags: {},
        attributes: {
          ingress: [
            { fromPort: 22, toPort: 22, protocol: "tcp", cidrs: ["0.0.0.0/0", "198.51.100.0/24"], sourceGroupIds: [] },
          ],
        },
      },
    ],
  };
  const sg = redactGraph(g).nodes.find((n) => n.type === "aws::ec2::security-group")!;
  const rules = sg.attributes["ingress"] as Array<{ cidrs: string[]; fromPort: number }>;
  assert.equal(rules[0]!.fromPort, 22);
  assert.deepEqual(rules[0]!.cidrs, ["0.0.0.0/0"]);
});
