/**
 * @kumomiru/aws — the AWS SDK boundary. Read-only by construction; the policy
 * the scan role needs is generated from the actions declared here.
 */
export { makeSdkClient, DISCOVERY_ACTIONS } from "./client.js";
export { listEnabledRegions, REGION_ACTIONS } from "./regions.js";
export { sts } from "./sts.js";
export type { StsApi, AssumeScanRoleInput } from "./sts.js";
export {
  LEAST_PRIVILEGE_POLICY,
  DENIED_ACTION_PREFIXES,
  policyActions,
  deniedActionsPresent,
} from "./policy.js";
export { PHASE3_ACTIONS, PHASE3_CAPABILITIES, parseCredentialReport } from "./collectors.js";
export { TRANCHE_B_ACTIONS } from "./collectors-b.js";
export { FEED_ACTIONS } from "./feeds.js";
