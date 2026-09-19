import { test } from "node:test";
import assert from "node:assert/strict";

import { isDue, assertValidCron } from "../src/schedule.js";

test("isDue: never scanned is due; otherwise next occurrence after last start", () => {
  const every6h = "0 */6 * * *";
  assert.equal(isDue(every6h, null, new Date("2026-09-19T00:01:00Z")), true);
  assert.equal(
    isDue(every6h, "2026-09-19T00:00:30Z", new Date("2026-09-19T05:59:00Z")),
    false,
  );
  assert.equal(
    isDue(every6h, "2026-09-19T00:00:30Z", new Date("2026-09-19T06:00:00Z")),
    true,
  );
});

test("assertValidCron rejects garbage", () => {
  assertValidCron("*/5 * * * *");
  assert.throws(() => assertValidCron("every tuesday"));
});
