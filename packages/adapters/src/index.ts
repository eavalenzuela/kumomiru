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
  DiscoverOptions,
  DiscoverScope,
} from "./aws-live/index.js";
// Combine per-region + global graphs of one account (scheduled scans).
export { mergeGraphs } from "./common/merge.js";
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
  DiscoveredUser,
} from "./aws-live/client.js";

// IAM analysis pass (the shared "brain") + its policy evaluator.
export { analyzeAssumeRole } from "./analysis/iam.js";
export type {
  AnalyzedPrincipal,
  AssumeTrustEntry,
  IamAnalysisResult,
} from "./analysis/iam.js";
export { evaluate as evaluatePolicy } from "./analysis/policy.js";
export type { PolicyStatement, Decision, EvalResult } from "./analysis/policy.js";

// Dataflow analysis pass (SG reachability + explicit references).
export { analyzeDataflow } from "./analysis/dataflow.js";
export type {
  DataflowInput,
  DataflowResult,
  DataflowMember,
  DataflowIngress,
  DataflowReference,
} from "./analysis/dataflow.js";
