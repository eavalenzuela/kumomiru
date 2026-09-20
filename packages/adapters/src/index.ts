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
// The rule engine's `requires` vocabulary: what discovery collects.
export { DISCOVERY_CAPABILITIES } from "./aws-live/discover.js";
export type { IngressRule } from "./common/ingress.js";
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
  DiscoveredBucket,
  DiscoveredVolume,
  DiscoveredSnapshot,
  DiscoveredKmsKey,
  DiscoveredTrail,
  CredentialReportRow,
  AccountSummary,
  RegionSettings,
  DiscoveredRouteTable,
  DiscoveredNatGateway,
  DiscoveredVpcPeering,
  DiscoveredVpcEndpoint,
  DiscoveredNetworkAcl,
  DiscoveredLoadBalancer,
  DiscoveredEcsCluster,
  DiscoveredTaskDefinition,
  DiscoveredEksCluster,
  DiscoveredQueue,
  DiscoveredTopic,
  DiscoveredDynamoTable,
  DiscoveredEcrRepository,
  DiscoveredAutoScalingGroup,
  DiscoveredLaunchTemplate,
  DiscoveredFileSystem,
  DiscoveredDistribution,
  DiscoveredRestApi,
  DiscoveredDbCluster,
  DiscoveredDbSnapshot,
  DiscoveredSsmParameter,
  AsffFinding,
  SecurityHubFeed,
  AccessAnalyzerFinding,
  AccessAnalyzerFeed,
} from "./aws-live/client.js";
// Managed feed mappers (Security Hub ASFF, IAM Access Analyzer).
export { mapAsffFindings, asffTypeToKumomiru } from "./feeds/asff.js";
export { mapAccessAnalyzerFindings } from "./feeds/accessanalyzer.js";
export { OPTIONAL_CAPABILITIES } from "./aws-live/client.js";

// IAM analysis passes (the shared "brain") + the policy evaluator.
export { analyzeAssumeRole } from "./analysis/iam.js";
export { analyzeResourceAccess } from "./analysis/resourceAccess.js";
export type { AccessResource, ResourceAccessResult } from "./analysis/resourceAccess.js";
export { projectPolicyDocument, conditionKeysOf, parsePolicyDoc } from "./common/policy-doc.js";
export type {
  AnalyzedPrincipal,
  AssumeTrustEntry,
  IamAnalysisResult,
} from "./analysis/iam.js";
export { evaluate as evaluatePolicy } from "./analysis/policy.js";
export type { PolicyStatement, PolicyPrincipal, Decision, EvalResult } from "./analysis/policy.js";

// Dataflow analysis pass (SG reachability + explicit references).
export { analyzeDataflow } from "./analysis/dataflow.js";
export type {
  DataflowInput,
  DataflowResult,
  DataflowMember,
  DataflowIngress,
  DataflowReference,
} from "./analysis/dataflow.js";
