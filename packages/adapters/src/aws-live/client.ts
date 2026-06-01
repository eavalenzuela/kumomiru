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
  }>;
  tags: Record<string, string>;
}

/**
 * Read-only discovery client. The live adapter calls these; a fake implements
 * them in tests. `accountId` identifies the scanned account (from STS
 * GetCallerIdentity in the real impl).
 */
export interface DiscoveryClient {
  accountId(): Promise<string>;
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
}
