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
  subnetIds: string[];
  tags: Record<string, string>;
}

export interface DiscoveredFunction {
  functionName: string;
  runtime?: string;
  /** Env var keys+values; values scanned for secrets, never stored raw. */
  environment: Record<string, string>;
  tags: Record<string, string>;
}

export interface DiscoveredSecret {
  arn: string;
  name: string;
  /** We list the secret but NEVER fetch its value. */
  tags: Record<string, string>;
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
}
