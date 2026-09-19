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
} as const;
