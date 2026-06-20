import { test } from "node:test";
import assert from "node:assert/strict";

import { scanText, scanRecord } from "../src/common/sanitize.js";

test("detects an unquoted KEY=VALUE env-var secret (the primary real case)", () => {
  // Regression: the previous generic detector required quotes around the value
  // and silently missed bare assignments like Lambda/ECS env vars.
  const res = scanRecord({ DB_PASSWORD: "hunter2supersecret" });
  assert.equal(res.found, true);
  assert.deepEqual(res.keys, ["DB_PASSWORD"]);
  assert.ok(res.kinds.includes("generic-secret-assignment"));
});

test("detects a quoted secret assignment too", () => {
  assert.equal(scanText('api_key: "abcdefgh1234"').found, true);
});

test("detects AWS access key ids and private key headers", () => {
  assert.equal(scanText("AKIAIOSFODNN7EXAMPLE").found, true);
  assert.equal(
    scanText("-----BEGIN RSA PRIVATE KEY-----\nMII...").found,
    true,
  );
});

test("detects high-signal provider tokens", () => {
  assert.ok(scanText("ghp_" + "a".repeat(36)).found, "github token");
  assert.ok(scanText("xoxb-12345678901-abcd").found, "slack token");
  assert.ok(scanText("sk_live_" + "a".repeat(20)).found, "stripe key");
  assert.ok(
    scanText("postgres://admin:s3cr3tp@db.internal:5432/app").found,
    "url credentials",
  );
});

test("does not flag innocuous text", () => {
  assert.equal(scanText("just a normal description").found, false);
  assert.equal(scanText("port=5432").found, false);
  // A short value under the length threshold should not trip the detector.
  assert.equal(scanRecord({ NOTE: "ok" }).found, false);
});

test("scanRecord ignores non-string values", () => {
  const res = scanRecord({ count: 5 as unknown as string, flag: true as unknown as string });
  assert.equal(res.found, false);
});
