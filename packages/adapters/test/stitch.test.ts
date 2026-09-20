import { test } from "node:test";
import assert from "node:assert/strict";

import { checkReferentialIntegrity } from "@kumomiru/graph";
import { discoverGraph, stitchKnownAccounts, type DiscoveryClient } from "../src/index.js";

const ACCOUNT = "123456789012";
const SIBLING = "999988887777";
const STRANGER = "111122223333";

function client(): DiscoveryClient {
  return {
    accountId: async () => ACCOUNT,
    region: () => "us-east-1",
    vpcs: async () => [], subnets: async () => [], internetGateways: async () => [], securityGroups: async () => [],
    instances: async () => [], dbInstances: async () => [], functions: async () => [], secrets: async () => [],
    roles: async () => [
      { roleName: "Deploy", arn: `arn:aws:iam::${ACCOUNT}:role/Deploy`, trustedPrincipals: [{ type: "aws", value: `arn:aws:iam::${SIBLING}:root` }], tags: {} },
      { roleName: "Vendor", arn: `arn:aws:iam::${ACCOUNT}:role/Vendor`, trustedPrincipals: [{ type: "aws", value: `arn:aws:iam::${STRANGER}:root`, conditionKeys: ["sts:ExternalId"] }], tags: {} },
    ],
  };
}

test("stitchKnownAccounts marks sibling-account principals and steps their findings down; strangers untouched", async () => {
  const raw = await discoverGraph(client());
  const g = stitchKnownAccounts({ ...raw, meta: { ...raw.meta, accountId: ACCOUNT } }, new Set([ACCOUNT, SIBLING]));
  assert.deepEqual(checkReferentialIntegrity(g), []);

  const sib = g.nodes.find((n) => n.type === "aws::iam::external-principal" && n.account === SIBLING)!;
  assert.equal(sib.attributes["knownAccount"], true);
  assert.match(sib.name, /registered account/);
  const str = g.nodes.find((n) => n.type === "aws::iam::external-principal" && n.account === STRANGER)!;
  assert.equal(str.attributes["knownAccount"], undefined);

  const sibEdge = g.edges.find((e) => e.source === sib.id)!;
  assert.equal(sibEdge.attributes["knownAccount"], true);
  assert.equal(g.edges.find((e) => e.source === str.id)!.attributes["knownAccount"], undefined);

  const deploy = g.findings.find((f) => f.nodeId === `arn:aws:iam::${ACCOUNT}:role/Deploy`)!;
  assert.equal(deploy.severity, "high", "critical → high for in-estate trust");
  assert.match(deploy.detail, /registered in kumomiru/);
  assert.equal(deploy.evidence?.["knownAccount"], SIBLING);
  const vendor = g.findings.find((f) => f.nodeId === `arn:aws:iam::${ACCOUNT}:role/Vendor`)!;
  assert.equal(vendor.severity, "high", "stranger with ExternalId stays high, unchanged");
  assert.ok(!vendor.detail.includes("registered in kumomiru"));

  // No known accounts → identical graph.
  const same = stitchKnownAccounts(raw, new Set([ACCOUNT]));
  assert.deepEqual(same, raw);
});
