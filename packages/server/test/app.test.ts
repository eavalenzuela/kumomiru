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
