import type { Graph } from "./types.js";

/**
 * A hand-authored sample graph. Its job is to exercise every concept in the
 * spine before any real adapter exists, so the viewer and validators have
 * something realistic to render and test against:
 *
 *   - containment hierarchy: account -> region -> VPC -> subnet -> resource
 *   - all three lenses: network, iam, dataflow
 *   - a sanitized secret (attributes carry `secretPresent`, never a value)
 *   - findings: a plaintext-secret finding and an external-can-assume finding
 *
 * Topology: one VPC with a public and a private subnet. A web instance in the
 * public subnet (reachable from the internet via an IGW) talks to an RDS
 * database in the private subnet. A Lambda reads from a DynamoDB table and from
 * a Secrets Manager secret. An EC2 role can be assumed by the instance, and an
 * external account principal can assume an admin role (the scary finding).
 */

const ACCOUNT = "123456789012";
const REGION = "us-east-1";

// --- containment scaffold ----------------------------------------------------
const accountId = `aws::account::${ACCOUNT}`;
const regionId = `aws::region::${ACCOUNT}::${REGION}`;
const vpcId = `arn:aws:ec2:${REGION}:${ACCOUNT}:vpc/vpc-0a1b2c3d`;
const publicSubnetId = `arn:aws:ec2:${REGION}:${ACCOUNT}:subnet/subnet-public1`;
const privateSubnetId = `arn:aws:ec2:${REGION}:${ACCOUNT}:subnet/subnet-private1`;

// --- resources ---------------------------------------------------------------
const igwId = `arn:aws:ec2:${REGION}:${ACCOUNT}:internet-gateway/igw-00112233`;
const webInstanceId = `arn:aws:ec2:${REGION}:${ACCOUNT}:instance/i-0web00001`;
const dbId = `arn:aws:rds:${REGION}:${ACCOUNT}:db:app-postgres`;
const lambdaId = `arn:aws:lambda:${REGION}:${ACCOUNT}:function:report-generator`;
const tableId = `arn:aws:dynamodb:${REGION}:${ACCOUNT}:table/reports`;
const secretId = `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:db-credentials-AbCdEf`;

// --- IAM principals ----------------------------------------------------------
const ec2RoleId = `arn:aws:iam::${ACCOUNT}:role/web-instance-role`;
const lambdaRoleId = `arn:aws:iam::${ACCOUNT}:role/report-generator-role`;
const adminRoleId = `arn:aws:iam::${ACCOUNT}:role/OrganizationAdmin`;
const externalPrincipalId = `arn:aws:iam::999988887777:root`;

export const sampleGraph: Graph = {
  meta: {
    generatedAt: "2026-05-31T00:00:00.000Z",
    source: "sample",
    provider: "aws",
  },
  nodes: [
    // containment
    {
      id: accountId,
      type: "aws::account",
      name: "demo-account",
      account: ACCOUNT,
      tags: {},
      attributes: {},
    },
    {
      id: regionId,
      type: "aws::region",
      name: REGION,
      account: ACCOUNT,
      region: REGION,
      parent: accountId,
      tags: {},
      attributes: {},
    },
    {
      id: vpcId,
      type: "aws::ec2::vpc",
      name: "main-vpc",
      account: ACCOUNT,
      region: REGION,
      parent: regionId,
      tags: { Name: "main-vpc" },
      attributes: { cidrBlock: "10.0.0.0/16" },
    },
    {
      id: publicSubnetId,
      type: "aws::ec2::subnet",
      name: "public-1a",
      account: ACCOUNT,
      region: REGION,
      parent: vpcId,
      tags: { Name: "public-1a", Tier: "public" },
      attributes: { cidrBlock: "10.0.1.0/24", mapPublicIpOnLaunch: true },
    },
    {
      id: privateSubnetId,
      type: "aws::ec2::subnet",
      name: "private-1a",
      account: ACCOUNT,
      region: REGION,
      parent: vpcId,
      tags: { Name: "private-1a", Tier: "private" },
      attributes: { cidrBlock: "10.0.2.0/24", mapPublicIpOnLaunch: false },
    },

    // resources
    {
      id: igwId,
      type: "aws::ec2::internet-gateway",
      name: "main-igw",
      account: ACCOUNT,
      region: REGION,
      parent: vpcId,
      tags: {},
      attributes: {},
    },
    {
      id: webInstanceId,
      type: "aws::ec2::instance",
      name: "web-server",
      account: ACCOUNT,
      region: REGION,
      parent: publicSubnetId,
      tags: { Name: "web-server", Role: "web" },
      attributes: {
        instanceType: "t3.small",
        publicIp: "203.0.113.10",
        // user-data contained a hard-coded key; the sanitization layer would
        // strip the value and leave a marker like this.
        userDataSecret: { secretPresent: true, kind: "aws-access-key" },
      },
    },
    {
      id: dbId,
      type: "aws::rds::db-instance",
      name: "app-postgres",
      account: ACCOUNT,
      region: REGION,
      parent: privateSubnetId,
      tags: { Name: "app-postgres" },
      attributes: { engine: "postgres", port: 5432, publiclyAccessible: false },
    },
    {
      id: lambdaId,
      type: "aws::lambda::function",
      name: "report-generator",
      account: ACCOUNT,
      region: REGION,
      parent: privateSubnetId,
      tags: {},
      attributes: { runtime: "nodejs20.x" },
    },
    {
      id: tableId,
      type: "aws::dynamodb::table",
      name: "reports",
      account: ACCOUNT,
      region: REGION,
      parent: regionId,
      tags: {},
      attributes: {},
    },
    {
      id: secretId,
      type: "aws::secretsmanager::secret",
      name: "db-credentials",
      account: ACCOUNT,
      region: REGION,
      parent: regionId,
      tags: {},
      // We list the secret as a node but NEVER resolve its value.
      attributes: { secretPresent: true, valueResolved: false },
    },

    // IAM principals
    {
      id: ec2RoleId,
      type: "aws::iam::role",
      name: "web-instance-role",
      account: ACCOUNT,
      parent: accountId,
      tags: {},
      attributes: { trustedService: "ec2.amazonaws.com" },
    },
    {
      id: lambdaRoleId,
      type: "aws::iam::role",
      name: "report-generator-role",
      account: ACCOUNT,
      parent: accountId,
      tags: {},
      attributes: { trustedService: "lambda.amazonaws.com" },
    },
    {
      id: adminRoleId,
      type: "aws::iam::role",
      name: "OrganizationAdmin",
      account: ACCOUNT,
      parent: accountId,
      tags: {},
      attributes: { managedPolicies: ["AdministratorAccess"] },
    },
    {
      id: externalPrincipalId,
      type: "aws::iam::external-principal",
      name: "external-account-999988887777",
      account: "999988887777",
      parent: accountId,
      tags: {},
      attributes: { external: true },
    },
  ],
  edges: [
    // --- network lens --------------------------------------------------------
    {
      id: "e-igw-vpc",
      source: igwId,
      target: vpcId,
      relationship: "attached-to",
      lens: "network",
      attributes: {},
    },
    {
      id: "e-internet-web",
      source: igwId,
      target: webInstanceId,
      relationship: "allows-ingress",
      lens: "network",
      attributes: { ports: "443,80", from: "0.0.0.0/0", internetFacing: true },
    },
    {
      id: "e-web-db",
      source: webInstanceId,
      target: dbId,
      relationship: "allows-ingress",
      lens: "network",
      attributes: { port: 5432 },
    },

    // --- dataflow lens -------------------------------------------------------
    {
      id: "e-web-db-flow",
      source: webInstanceId,
      target: dbId,
      relationship: "reads-from",
      lens: "dataflow",
      attributes: { protocol: "postgres" },
    },
    {
      id: "e-lambda-table",
      source: lambdaId,
      target: tableId,
      relationship: "reads-from",
      lens: "dataflow",
      attributes: {},
    },
    {
      id: "e-lambda-secret",
      source: lambdaId,
      target: secretId,
      relationship: "reads-from",
      lens: "dataflow",
      attributes: { note: "reads credentials at runtime" },
    },

    // --- iam lens (assume-role graph only, per milestone scope) ---------------
    {
      id: "e-ec2-assume",
      source: webInstanceId,
      target: ec2RoleId,
      relationship: "can-assume",
      lens: "iam",
      attributes: { via: "instance-profile" },
    },
    {
      id: "e-lambda-assume",
      source: lambdaId,
      target: lambdaRoleId,
      relationship: "can-assume",
      lens: "iam",
      attributes: { via: "execution-role" },
    },
    {
      id: "e-lambdarole-secret",
      source: lambdaRoleId,
      target: secretId,
      relationship: "can-access",
      lens: "iam",
      attributes: { actions: ["secretsmanager:GetSecretValue"] },
    },
    {
      id: "e-external-admin",
      source: externalPrincipalId,
      target: adminRoleId,
      relationship: "can-assume",
      lens: "iam",
      // both sides confirmed: external account is named in the trust policy
      attributes: { trustConfirmed: true, conditions: [] },
    },
  ],
  findings: [
    {
      id: "f-plaintext-secret",
      severity: "high",
      kind: "plaintext-secret",
      nodeId: webInstanceId,
      title: "Plaintext secret detected in EC2 user-data",
      detail:
        "The web-server instance's user-data contains what looks like an AWS access key. The value was redacted at ingestion; rotate the key and move it to Secrets Manager.",
    },
    {
      id: "f-external-admin",
      severity: "critical",
      kind: "external-can-assume",
      nodeId: adminRoleId,
      title: "External account can assume an admin role",
      detail:
        "Role OrganizationAdmin (AdministratorAccess) trusts external account 999988887777 with no condition (e.g. ExternalId or MFA). Any principal in that account can gain full admin.",
    },
  ],
};
