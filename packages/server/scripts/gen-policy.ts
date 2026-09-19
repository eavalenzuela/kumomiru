/**
 * Regenerate docs/least-privilege-policy.json from the in-code policy
 * (`LEAST_PRIVILEGE_POLICY` in src/routes/policy.ts). The test suite asserts
 * the file matches, so run this after changing the policy:
 *
 *   pnpm policy:gen
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { LEAST_PRIVILEGE_POLICY, deniedActionsPresent } from "../src/routes/policy.js";

const denied = deniedActionsPresent();
if (denied.length > 0) {
  console.error(`refusing to generate: denied actions present: ${denied.join(", ")}`);
  process.exit(1);
}

const out = fileURLToPath(
  new URL("../../../docs/least-privilege-policy.json", import.meta.url),
);
writeFileSync(out, JSON.stringify(LEAST_PRIVILEGE_POLICY, null, 2) + "\n");
console.log(`wrote ${out}`);
