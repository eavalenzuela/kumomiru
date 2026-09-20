/**
 * The discovery surface: a narrow, read-only interface describing exactly the
 * data the live adapter needs, decoupled from the AWS SDK. The graph-building
 * logic depends only on this interface, so:
 *   - it is unit-testable with a fake client (no AWS, no creds), and
 *   - the real SDK-backed implementation is a thin, swappable layer.
 *
 * These shapes are intentionally minimal projections of the AWS API responses
 * — only the fields the adapter maps. Everything here is read-only; there is no
 * method that mutates cloud state, by construction.
 */

import type { PolicyStatement } from "../analysis/policy.js";

export interface DiscoveredVpc {
  vpcId: string;
  cidrBlock?: string;
  /** Whether at least one VPC flow log is configured (from DescribeFlowLogs). */
  flowLogsEnabled?: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredSubnet {
  subnetId: string;
  vpcId: string;
  cidrBlock?: string;
  availabilityZone?: string;
  mapPublicIpOnLaunch?: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredInternetGateway {
  internetGatewayId: string;
  /** vpcId it is attached to, if any. */
  attachedVpcId?: string;
  tags: Record<string, string>;
}

export interface DiscoveredSecurityGroup {
  groupId: string;
  groupName?: string;
  vpcId?: string;
  /** Simplified ingress rules. */
  ingress: Array<{
    fromPort?: number;
    toPort?: number;
    ipProtocol?: string;
    /** CIDR ranges this rule allows from. */
    cidrs: string[];
    /** Source security-group ids this rule allows from (UserIdGroupPairs). */
    sourceGroupIds?: string[];
  }>;
  tags: Record<string, string>;
}

export interface DiscoveredInstance {
  instanceId: string;
  subnetId?: string;
  instanceType?: string;
  publicIp?: string;
  privateIp?: string;
  securityGroupIds: string[];
  /** Decoded EC2 user-data, if any. Scanned for secrets, never stored raw. */
  userData?: string;
  /** MetadataOptions.HttpTokens === "required" (IMDSv2 enforced). */
  imdsv2Required?: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredDbInstance {
  dbInstanceIdentifier: string;
  engine?: string;
  port?: number;
  publiclyAccessible?: boolean;
  storageEncrypted?: boolean;
  subnetIds: string[];
  tags: Record<string, string>;
}

export interface DiscoveredFunction {
  functionName: string;
  runtime?: string;
  /** Env var keys+values; values scanned for secrets, never stored raw. */
  environment: Record<string, string>;
  /** Resource-based policy statements (lambda:GetPolicy), if collected. */
  resourcePolicy?: PolicyStatement[];
  /** Auth types of any function URLs ("NONE" means unauthenticated). */
  urlAuthTypes?: string[];
  tags: Record<string, string>;
}

export interface DiscoveredSecret {
  arn: string;
  name: string;
  rotationEnabled?: boolean;
  /** Resource policy statements, if collected. */
  resourcePolicy?: PolicyStatement[];
  /** We list the secret but NEVER fetch its value. */
  tags: Record<string, string>;
}

// --- Phase 3 resources (all optional on the client) ---------------------------

export interface DiscoveredBucket {
  name: string;
  arn: string;
  region: string;
  publicAccessBlock?: {
    blockPublicAcls: boolean;
    ignorePublicAcls: boolean;
    blockPublicPolicy: boolean;
    restrictPublicBuckets: boolean;
  };
  /** From GetBucketPolicyStatus; AWS's own verdict on the policy. */
  policyIsPublic?: boolean;
  policyStatements?: PolicyStatement[];
  /** e.g. "AES256" | "aws:kms" | undefined when no default encryption. */
  encryption?: string;
  versioning?: boolean;
  loggingEnabled?: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredVolume {
  volumeId: string;
  encrypted: boolean;
  attachedInstanceIds: string[];
  sizeGiB?: number;
  tags: Record<string, string>;
}

export interface DiscoveredSnapshot {
  snapshotId: string;
  volumeId?: string;
  encrypted: boolean;
  /** createVolumePermission includes group "all". */
  public: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredKmsKey {
  keyId: string;
  arn: string;
  /** "AWS" for AWS-managed keys (rotation is AWS's job), "CUSTOMER" otherwise. */
  manager: "AWS" | "CUSTOMER";
  enabled: boolean;
  rotationEnabled?: boolean;
  policyStatements?: PolicyStatement[];
  aliases: string[];
  tags: Record<string, string>;
}

export interface DiscoveredTrail {
  name: string;
  arn: string;
  homeRegion?: string;
  isMultiRegion: boolean;
  isLogging: boolean;
  logFileValidationEnabled: boolean;
  kmsKeyId?: string;
  /** Management events are recorded (read and write). */
  managementEvents: boolean;
}

export interface CredentialReportRow {
  /** `<root_account>` for the root user. */
  user: string;
  arn: string;
  passwordEnabled: boolean;
  passwordLastUsed?: string;
  mfaActive: boolean;
  accessKey1Active: boolean;
  accessKey1LastRotated?: string;
  accessKey1LastUsed?: string;
  accessKey2Active: boolean;
  accessKey2LastRotated?: string;
  accessKey2LastUsed?: string;
}

export interface AccountSummary {
  rootMfaEnabled: boolean;
  rootAccessKeysPresent: boolean;
  passwordPolicy: {
    minimumLength: number;
    requireSymbols: boolean;
    requireNumbers: boolean;
    requireUppercase: boolean;
    requireLowercase: boolean;
    maxAgeDays?: number;
    reusePrevention?: number;
  } | null;
  /** Account-level S3 Public Access Block, all four flags. */
  s3PublicAccessBlock: {
    blockPublicAcls: boolean;
    ignorePublicAcls: boolean;
    blockPublicPolicy: boolean;
    restrictPublicBuckets: boolean;
  } | null;
}

// --- Tranche B resources (all optional on the client) ---------------------------

export interface DiscoveredRouteTable {
  routeTableId: string;
  vpcId: string;
  /** Subnets explicitly associated; the main table covers the rest. */
  subnetIds: string[];
  main: boolean;
  routes: Array<{
    destination: string;
    targetType: "igw" | "nat" | "peering" | "vpce" | "local" | "instance" | "other";
    targetId?: string;
  }>;
  tags: Record<string, string>;
}

export interface DiscoveredNatGateway {
  natGatewayId: string;
  vpcId?: string;
  subnetId?: string;
  tags: Record<string, string>;
}

export interface DiscoveredVpcPeering {
  peeringId: string;
  requesterVpcId?: string;
  requesterAccount?: string;
  accepterVpcId?: string;
  accepterAccount?: string;
  status?: string;
  tags: Record<string, string>;
}

export interface DiscoveredVpcEndpoint {
  endpointId: string;
  vpcId?: string;
  serviceName: string;
  type: string;
  tags: Record<string, string>;
}

export interface DiscoveredNetworkAcl {
  aclId: string;
  vpcId?: string;
  subnetIds: string[];
  isDefault: boolean;
  entries: Array<{
    ruleNumber: number;
    egress: boolean;
    /** "-1" for all, or a protocol number/name. */
    protocol: string;
    fromPort?: number;
    toPort?: number;
    cidr?: string;
    action: "allow" | "deny";
  }>;
  tags: Record<string, string>;
}

export interface DiscoveredLoadBalancer {
  arn: string;
  name: string;
  type: "application" | "network" | "gateway";
  scheme: "internet-facing" | "internal";
  vpcId?: string;
  subnetIds: string[];
  securityGroupIds: string[];
  dnsName?: string;
  accessLogsEnabled?: boolean;
  listeners: Array<{ port: number; protocol: string; redirectsToHttps: boolean }>;
  /** Targets by instance id, IP, or Lambda ARN. */
  targets: Array<{ targetGroupArn: string; targetType: string; id: string; port?: number }>;
  tags: Record<string, string>;
}

export interface DiscoveredEcsCluster {
  arn: string;
  name: string;
  services: Array<{
    arn: string;
    name: string;
    taskDefinitionArn?: string;
    launchType?: string;
    assignPublicIp: boolean;
    subnetIds: string[];
    securityGroupIds: string[];
  }>;
  tags: Record<string, string>;
}

export interface DiscoveredTaskDefinition {
  arn: string;
  family: string;
  /** Container env vars, scanned for secrets, never stored raw. */
  containers: Array<{ name: string; image?: string; environment: Record<string, string> }>;
  tags: Record<string, string>;
}

export interface DiscoveredEksCluster {
  arn: string;
  name: string;
  version?: string;
  vpcId?: string;
  subnetIds: string[];
  securityGroupIds: string[];
  endpointPublicAccess: boolean;
  endpointPrivateAccess: boolean;
  publicAccessCidrs: string[];
  /** Any control-plane log type enabled. */
  loggingEnabled: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredQueue {
  arn: string;
  name: string;
  kmsEncrypted: boolean;
  policyStatements?: PolicyStatement[];
  tags: Record<string, string>;
}

export interface DiscoveredTopic {
  arn: string;
  name: string;
  kmsEncrypted: boolean;
  policyStatements?: PolicyStatement[];
  tags: Record<string, string>;
}

export interface DiscoveredDynamoTable {
  arn: string;
  name: string;
  pitrEnabled?: boolean;
  deletionProtection?: boolean;
  kmsKeyArn?: string;
  tags: Record<string, string>;
}

export interface DiscoveredEcrRepository {
  arn: string;
  name: string;
  scanOnPush: boolean;
  tagImmutability: boolean;
  lifecyclePolicy: boolean;
  policyStatements?: PolicyStatement[];
  tags: Record<string, string>;
}

export interface DiscoveredAutoScalingGroup {
  arn: string;
  name: string;
  launchTemplateId?: string;
  launchConfigurationName?: string;
  instanceIds: string[];
  subnetIds: string[];
  tags: Record<string, string>;
}

export interface DiscoveredLaunchTemplate {
  launchTemplateId: string;
  name: string;
  /** Decoded user-data of the default/latest version; scanned, never stored raw. */
  userData?: string;
  imdsv2Required?: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredFileSystem {
  arn: string;
  fileSystemId: string;
  name?: string;
  encrypted: boolean;
  kmsKeyId?: string;
  policyStatements?: PolicyStatement[];
  tags: Record<string, string>;
}

export interface DiscoveredDistribution {
  arn: string;
  id: string;
  domainName: string;
  enabled: boolean;
  /** Default cache behavior: "allow-all" | "redirect-to-https" | "https-only". */
  viewerProtocolPolicy: string;
  loggingEnabled: boolean;
  origins: Array<{ id: string; domainName: string; type: "s3" | "custom" }>;
  tags: Record<string, string>;
}

export interface DiscoveredRestApi {
  id: string;
  arn: string;
  name: string;
  stages: Array<{ name: string; loggingEnabled: boolean; tracingEnabled: boolean }>;
  tags: Record<string, string>;
}

export interface DiscoveredDbCluster {
  arn: string;
  identifier: string;
  engine?: string;
  storageEncrypted?: boolean;
  memberInstanceIdentifiers: string[];
  tags: Record<string, string>;
}

export interface DiscoveredDbSnapshot {
  arn: string;
  identifier: string;
  /** Instance or cluster snapshot. */
  kind: "instance" | "cluster";
  encrypted: boolean;
  /** restore attribute includes "all". */
  public: boolean;
  tags: Record<string, string>;
}

export interface DiscoveredSsmParameter {
  arn: string;
  name: string;
  /** "String" | "StringList" | "SecureString" — values are NEVER read. */
  type: string;
}

// --- Managed feeds (Phase 4) ------------------------------------------------------

/** A Security Hub finding projected from ASFF to what the feed mapper needs. */
export interface AsffFinding {
  id: string;
  productName?: string;
  generatorId?: string;
  title: string;
  description?: string;
  /** INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL */
  severityLabel?: string;
  /** PASSED | FAILED | WARNING | NOT_AVAILABLE (control findings only). */
  complianceStatus?: string;
  /** e.g. "EC2.13" — the FSBP-style security control id. */
  securityControlId?: string;
  resourceIds: string[];
  resourceTypes: string[];
  workflowStatus?: string;
  updatedAt?: string;
  remediationText?: string;
  remediationUrl?: string;
}

export interface SecurityHubFeed {
  enabled: boolean;
  findings: AsffFinding[];
}

/** An IAM Access Analyzer external-access finding (analyzer type ACCOUNT or ORGANIZATION). */
export interface AccessAnalyzerFinding {
  id: string;
  resourceArn: string;
  resourceType: string;
  /** Principal that has access: account id, ARN, federated id, or "*" when public. */
  principal?: string;
  isPublic: boolean;
  actions: string[];
  /** Condition keys on the granting statement, when Access Analyzer reports them. */
  conditionKeys: string[];
  status: string;
  updatedAt?: string;
}

export interface AccessAnalyzerFeed {
  enabled: boolean;
  findings: AccessAnalyzerFinding[];
}

export interface RegionSettings {
  ebsEncryptionByDefault?: boolean;
  configRecorderEnabled?: boolean;
  guardDutyEnabled?: boolean;
}

export interface DiscoveredRole {
  roleName: string;
  arn: string;
  /** Parsed trust policy principals: who may assume this role. */
  trustedPrincipals: Array<{
    /** "service" | "aws" | "federated". */
    type: string;
    /** e.g. "ec2.amazonaws.com" or an account/role ARN. */
    value: string;
    /** Condition keys gating this trust entry (ExternalId, MFA, ...). */
    conditionKeys?: string[];
  }>;
  /**
   * The role's identity-policy statements, projected to what the IAM pass
   * evaluates. Drives the "both sides" assume-role check (a role can only
   * assume another role if its OWN identity policy allows sts:AssumeRole). May
   * be omitted by adapters that don't yet collect identity policies.
   */
  identityStatements?: PolicyStatement[];
  tags: Record<string, string>;
}

/**
 * An IAM user — a first-class assume-role *source* principal. Like roles, users
 * carry identity-policy statements; unlike roles they have no trust policy (you
 * don't assume a user).
 */
export interface DiscoveredUser {
  userName: string;
  arn: string;
  identityStatements?: PolicyStatement[];
  tags: Record<string, string>;
}

/**
 * Read-only discovery client. The live adapter calls these; a fake implements
 * them in tests. `accountId` identifies the scanned account (from STS
 * GetCallerIdentity in the real impl).
 */
export interface DiscoveryClient {
  accountId(): Promise<string>;
  /**
   * ARN partition (`aws`, `aws-us-gov`, `aws-cn`). Optional: a client that
   * omits it is treated as the commercial partition. The live SDK client
   * derives it from the caller identity so node ids match the real ARNs IAM
   * returns in GovCloud and China accounts.
   */
  partition?(): Promise<string>;
  region(): string;
  vpcs(): Promise<DiscoveredVpc[]>;
  subnets(): Promise<DiscoveredSubnet[]>;
  internetGateways(): Promise<DiscoveredInternetGateway[]>;
  securityGroups(): Promise<DiscoveredSecurityGroup[]>;
  instances(): Promise<DiscoveredInstance[]>;
  dbInstances(): Promise<DiscoveredDbInstance[]>;
  functions(): Promise<DiscoveredFunction[]>;
  secrets(): Promise<DiscoveredSecret[]>;
  roles(): Promise<DiscoveredRole[]>;
  /**
   * IAM users. Optional: a client that only collects roles still produces a
   * valid (role-only) assume-role graph. The live SDK client implements it.
   */
  users?(): Promise<DiscoveredUser[]>;

  // --- Optional Phase 3 collectors. The rule engine's `requires` vocabulary
  // maps 1:1 to these; a client that lacks one leaves those rules
  // `not-assessed`. `capabilities()` declares which extras a client provides.
  capabilities?(): string[];
  /** Global. */
  accountSummary?(): Promise<AccountSummary>;
  /** Global. */
  credentialReport?(): Promise<CredentialReportRow[]>;
  /** Global: every trail visible from the account (shadow trails included). */
  cloudTrails?(): Promise<DiscoveredTrail[]>;
  /** Regional. */
  regionSettings?(): Promise<RegionSettings>;
  /** Regional: buckets whose location is this client's region. */
  s3Buckets?(): Promise<DiscoveredBucket[]>;
  /** Regional. */
  ebsVolumes?(): Promise<DiscoveredVolume[]>;
  /** Regional: snapshots owned by this account. */
  ebsSnapshots?(): Promise<DiscoveredSnapshot[]>;
  /** Regional. */
  kmsKeys?(): Promise<DiscoveredKmsKey[]>;

  // --- Tranche B (all regional unless noted) ----------------------------------
  routeTables?(): Promise<DiscoveredRouteTable[]>;
  natGateways?(): Promise<DiscoveredNatGateway[]>;
  vpcPeerings?(): Promise<DiscoveredVpcPeering[]>;
  vpcEndpoints?(): Promise<DiscoveredVpcEndpoint[]>;
  networkAcls?(): Promise<DiscoveredNetworkAcl[]>;
  loadBalancers?(): Promise<DiscoveredLoadBalancer[]>;
  ecsClusters?(): Promise<DiscoveredEcsCluster[]>;
  ecsTaskDefinitions?(): Promise<DiscoveredTaskDefinition[]>;
  eksClusters?(): Promise<DiscoveredEksCluster[]>;
  sqsQueues?(): Promise<DiscoveredQueue[]>;
  snsTopics?(): Promise<DiscoveredTopic[]>;
  dynamoTables?(): Promise<DiscoveredDynamoTable[]>;
  ecrRepositories?(): Promise<DiscoveredEcrRepository[]>;
  autoScalingGroups?(): Promise<DiscoveredAutoScalingGroup[]>;
  launchTemplates?(): Promise<DiscoveredLaunchTemplate[]>;
  fileSystems?(): Promise<DiscoveredFileSystem[]>;
  /** Global. */
  cloudFrontDistributions?(): Promise<DiscoveredDistribution[]>;
  restApis?(): Promise<DiscoveredRestApi[]>;
  dbClusters?(): Promise<DiscoveredDbCluster[]>;
  dbSnapshots?(): Promise<DiscoveredDbSnapshot[]>;
  ssmParameters?(): Promise<DiscoveredSsmParameter[]>;

  // --- Managed feeds (regional). `enabled: false` means the service is off in
  // this account/region; native rules then cover the same controls.
  securityHubFindings?(): Promise<SecurityHubFeed>;
  accessAnalyzerFindings?(): Promise<AccessAnalyzerFeed>;
}

/** Capability names for the optional collectors, keyed by client method. */
export const OPTIONAL_CAPABILITIES = {
  accountSummary: "iam:account-summary",
  credentialReport: "iam:credential-report",
  cloudTrails: "cloudtrail:trail",
  regionSettings: "account:region-settings",
  s3Buckets: "s3:bucket",
  ebsVolumes: "ec2:volume",
  ebsSnapshots: "ec2:snapshot",
  kmsKeys: "kms:key",
  routeTables: "ec2:route-table",
  natGateways: "ec2:nat-gateway",
  vpcPeerings: "ec2:vpc-peering",
  vpcEndpoints: "ec2:vpc-endpoint",
  networkAcls: "ec2:network-acl",
  loadBalancers: "elbv2:load-balancer",
  ecsClusters: "ecs:cluster",
  ecsTaskDefinitions: "ecs:task-definition",
  eksClusters: "eks:cluster",
  sqsQueues: "sqs:queue",
  snsTopics: "sns:topic",
  dynamoTables: "dynamodb:table",
  ecrRepositories: "ecr:repository",
  autoScalingGroups: "autoscaling:group",
  launchTemplates: "ec2:launch-template",
  fileSystems: "efs:file-system",
  cloudFrontDistributions: "cloudfront:distribution",
  restApis: "apigateway:rest-api",
  dbClusters: "rds:db-cluster",
  dbSnapshots: "rds:db-snapshot",
  ssmParameters: "ssm:parameter",
  securityHubFindings: "securityhub:findings",
  accessAnalyzerFindings: "accessanalyzer:findings",
} as const;
