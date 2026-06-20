import { test } from "node:test";
import assert from "node:assert/strict";

import { redactObject } from "../src/redact.js";

test("redactObject scrubs sensitive keys at any depth", () => {
  const input = {
    region: "us-east-1",
    accessKeyId: "AKIAEXAMPLE",
    nested: { secretAccessKey: "shhh", note: "fine" },
    list: [{ sessionToken: "tok" }, { ok: 1 }],
  };
  const out = redactObject(input) as Record<string, unknown>;
  assert.equal(out["region"], "us-east-1");
  assert.equal(out["accessKeyId"], "[REDACTED]");
  const nested = out["nested"] as Record<string, unknown>;
  assert.equal(nested["secretAccessKey"], "[REDACTED]");
  assert.equal(nested["note"], "fine");
  const list = out["list"] as Record<string, unknown>[];
  assert.equal(list[0]!["sessionToken"], "[REDACTED]");
  assert.equal(list[1]!["ok"], 1);
});

test("redactObject leaves a credential carried on an SDK-style error scrubbed", () => {
  // Mirrors the live route: an SDK error may attach request context with creds.
  const err = Object.assign(new Error("AccessDenied"), {
    $metadata: { httpStatusCode: 403 },
    credentials: { secretAccessKey: "leakme" },
  });
  const loggable = { name: err.name, message: err.message, ...err };
  const out = JSON.stringify(redactObject(loggable));
  assert.ok(!out.includes("leakme"), "secret must not survive redaction");
  assert.ok(out.includes("AccessDenied"), "non-secret message is kept");
});
