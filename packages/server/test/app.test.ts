import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { parseGraph } from "@kumomiru/graph";
import { buildApp } from "../src/app.js";

const tfstate = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/simple.tfstate.json", import.meta.url)),
    "utf8",
  ),
);

test("GET /health returns ok", async () => {
  const app = buildApp({ logger: false });
  const res = await app.inject({ method: "GET", url: "/health" });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), { status: "ok" });
  await app.close();
});

test("GET /sample returns a schema-valid graph", async () => {
  const app = buildApp({ logger: false });
  const res = await app.inject({ method: "GET", url: "/sample" });
  assert.equal(res.statusCode, 200);
  parseGraph(res.json()); // throws on schema mismatch
  await app.close();
});

test("POST /map/terraform normalizes state into a graph", async () => {
  const app = buildApp({ logger: false });
  const res = await app.inject({
    method: "POST",
    url: "/map/terraform",
    payload: tfstate,
  });
  assert.equal(res.statusCode, 200);
  const graph = parseGraph(res.json());
  assert.equal(graph.meta.source, "terraform-state");
  assert.ok(graph.nodes.some((n) => n.type === "aws::ec2::vpc"));
  await app.close();
});

test("POST /map/terraform rejects invalid state with 400", async () => {
  const app = buildApp({ logger: false });
  const res = await app.inject({
    method: "POST",
    url: "/map/terraform",
    payload: { not: "a terraform state" },
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, "invalid_terraform_state");
  await app.close();
});

test("GET /sample?redacted=1 strips data values but preserves topology", async () => {
  const app = buildApp({ logger: false });
  const full = (await app.inject({ method: "GET", url: "/sample" })).json();
  const red = (
    await app.inject({ method: "GET", url: "/sample?redacted=1" })
  ).json();
  parseGraph(red); // still schema-valid
  // Same node/edge counts — redaction is about values, not topology.
  assert.equal(red.nodes.length, full.nodes.length);
  assert.equal(red.edges.length, full.edges.length);
  const vpc = red.nodes.find((n) => n.type === "aws::ec2::vpc");
  // cidrBlock is a free-form value attribute → dropped; tag values → blanked.
  assert.equal(vpc.attributes.cidrBlock, undefined);
  assert.equal(vpc.tags.Name, "[redacted]");
  await app.close();
});

test("GET /policy/least-privilege serves a read-only policy without GetSecretValue", async () => {
  const app = buildApp({ logger: false });
  const res = await app.inject({
    method: "GET",
    url: "/policy/least-privilege",
  });
  assert.equal(res.statusCode, 200);
  const actions = res.json().Statement[0].Action;
  assert.ok(actions.includes("ec2:DescribeInstances"));
  assert.ok(actions.includes("ec2:DescribeInstanceAttribute")); // user-data
  assert.ok(actions.includes("iam:GetAccountAuthorizationDetails"));
  // The whole point: the scan role cannot read secret values.
  assert.ok(!actions.some((a) => a.toLowerCase().includes("getsecretvalue")));
  await app.close();
});
