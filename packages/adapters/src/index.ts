/**
 * @kumomiru/adapters — ingestion adapters that normalize cloud sources into the
 * shared @kumomiru/graph model.
 */
export type { Adapter } from "./contract.js";
export { terraformAdapter } from "./terraform/index.js";

// Live AWS discovery (in-memory credential broker + secret sanitization).
export {
  runLiveDiscovery,
  discoverGraph,
  CredentialBroker,
} from "./aws-live/index.js";
export type {
  AwsCredentials,
  CredentialMeta,
  DiscoveryClient,
  DiscoveryClientFactory,
} from "./aws-live/index.js";
// Discovery projection shapes — implemented by the server's SDK-backed client.
export type {
  DiscoveredVpc,
  DiscoveredSubnet,
  DiscoveredInternetGateway,
  DiscoveredSecurityGroup,
  DiscoveredInstance,
  DiscoveredDbInstance,
  DiscoveredFunction,
  DiscoveredSecret,
  DiscoveredRole,
} from "./aws-live/client.js";
