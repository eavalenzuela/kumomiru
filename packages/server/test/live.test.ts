import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph } from "@kumomiru/graph";
import type { DiscoveryClient } from "@kumomiru/adapters";
import { buildApp } from "../src/app.js";

const REGION = "us-east-1";

/** Minimal fake client — enough to produce a valid graph without AWS. */
function fakeClient(): DiscoveryClient {
  return {
    accountId: async () => "123456789012",
    region: () => REGION,
    vpcs: async () => [{ vpcId: "vpc-1", tags: { Name: "vpc" } }],
    subnets: async () => [],
    internetGateways: async () => [],
    securityGroups: async () => [],
    instances: async () => [],
    dbInstances: async () => [],
    functions: async () => [],
    secrets: async () => [],
    roles: async () => [],
  };
}

test("POST /map/live returns a graph using the injected fake client", async () => {
  const app = await buildApp({
    logger: false,
    discoveryClientFactory: () => fakeClient(),
  });
  const res = await app.inject({
    method: "POST",
    url: "/map/live",
    payload: {
      accessKeyId: "AKIAEXAMPLE",
      secretAccessKey: "shhh",
      sessionToken: "tok",
      region: REGION,
    },
  });
  assert.equal(res.statusCode, 200);
  const graph = parseGraph(res.json());
  assert.equal(graph.meta.source, "aws-live");
  await app.close();
});

test("POST /map/live rejects a body missing credentials with 400", async () => {
  const app = await buildApp({
    logger: false,
    discoveryClientFactory: () => fakeClient(),
  });
  const res = await app.inject({
    method: "POST",
    url: "/map/live",
    payload: { region: REGION },
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, "invalid_credentials_body");
  await app.close();
});

test("POST /map/live surfaces discovery failure as 502 without leaking", async () => {
  const app = await buildApp({
    logger: false,
    discoveryClientFactory: () => {
      throw new Error("boom");
    },
  });
  const res = await app.inject({
    method: "POST",
    url: "/map/live",
    payload: {
      accessKeyId: "AKIAEXAMPLE",
      secretAccessKey: "shhh",
      region: REGION,
    },
  });
  assert.equal(res.statusCode, 502);
  assert.equal(res.json().error, "discovery_failed");
  await app.close();
});
