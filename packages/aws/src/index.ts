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
