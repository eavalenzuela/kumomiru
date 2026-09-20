import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, checkReferentialIntegrity } from "@kumomiru/graph";
import { discoverGraph, mapAsffFindings, projectPolicyDocument, type DiscoveryClient, type AsffFinding } from "../src/index.js";

const ACCOUNT = "123456789012";
const REGION = "us-east-1";
const BUCKET = "arn:aws:s3:::open-bucket";
const SG = `arn:aws:ec2:${REGION}:${ACCOUNT}:security-group/sg-ssh`;

function asff(over: Partial<AsffFinding>): AsffFinding {
  return { id: "arn:aws:securityhub:us-east-1:123456789012:security-control/EC2.13/finding/1", title: "t", resourceIds: [], resourceTypes: [], ...over };
}

function client(feeds: { hub?: boolean; analyzer?: boolean } = {}): DiscoveryClient {
  return {
    accountId: async () => ACCOUNT,
    region: () => REGION,
    vpcs: async () => [{ vpcId: "vpc-1", tags: {} }],
    subnets: async () => [],
    internetGateways: async () => [],
    securityGroups: async () => [{ groupId: "sg-ssh", vpcId: "vpc-1", ingress: [{ fromPort: 22, toPort: 22, ipProtocol: "tcp", cidrs: ["0.0.0.0/0"] }], tags: {} }],
    instances: async () => [],
    dbInstances: async () => [],
    functions: async () => [],
    secrets: async () => [],
    roles: async () => [],
    s3Buckets: async () => [
      { name: "open-bucket", arn: BUCKET, region: REGION, policyIsPublic: true, tags: {},
        policyStatements: projectPolicyDocument({ Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: `${BUCKET}/*` }] }) },
    ],
    securityHubFindings: async () => ({
      enabled: feeds.hub ?? false,
      findings: [
        asff({ securityControlId: "EC2.13", complianceStatus: "FAILED", severityLabel: "HIGH", title: "Security groups should not allow ingress from 0.0.0.0/0 to port 22", resourceIds: [SG], resourceTypes: ["AwsEc2SecurityGroup"], productName: "Security Hub", updatedAt: "2026-09-19T01:00:00Z", remediationUrl: "https://docs.aws.amazon.com/..." }),
        asff({ id: "arn:...:EC2.14/finding/2", securityControlId: "EC2.14", complianceStatus: "PASSED", severityLabel: "INFORMATIONAL", resourceIds: [SG], resourceTypes: ["AwsEc2SecurityGroup"], productName: "Security Hub" }),
        asff({ id: "arn:...:IAM.6/finding/3", securityControlId: "IAM.6", complianceStatus: "FAILED", severityLabel: "CRITICAL", title: "Hardware MFA should be enabled for the root user", resourceIds: [`AWS::::Account:${ACCOUNT}`], resourceTypes: ["AwsAccount"], productName: "Security Hub" }),
        asff({ id: "arn:...:guardduty/4", productName: "GuardDuty", generatorId: "arn:aws:guardduty:...", title: "UnauthorizedAccess:EC2/SSHBruteForce", severityLabel: "MEDIUM", workflowStatus: "NEW", resourceIds: [`arn:aws:ec2:${REGION}:${ACCOUNT}:instance/i-x`], resourceTypes: ["AwsEc2Instance"] }),
        asff({ id: "arn:...:guardduty/5", productName: "GuardDuty", title: "old", severityLabel: "LOW", workflowStatus: "RESOLVED", resourceIds: [], resourceTypes: [] }),
      ],
    }),
    accessAnalyzerFindings: async () => ({
      enabled: feeds.analyzer ?? false,
      findings: [
        { id: "aa-1", resourceArn: BUCKET, resourceType: "AWS::S3::Bucket", isPublic: true, actions: ["s3:GetObject"], conditionKeys: [], status: "ACTIVE", updatedAt: "2026-09-19T00:00:00Z" },
        { id: "aa-2", resourceArn: "arn:aws:iam::123456789012:role/X", resourceType: "AWS::IAM::Role", principal: "999988887777", isPublic: false, actions: ["sts:AssumeRole"], conditionKeys: ["sts:ExternalId"], status: "ACTIVE" },
        { id: "aa-3", resourceArn: BUCKET, resourceType: "AWS::S3::Bucket", isPublic: true, actions: [], conditionKeys: [], status: "ARCHIVED" },
      ],
    }),
  };
}

test("mapAsffFindings: FAILED controls and NEW product findings become findings; PASSED only marks coverage", () => {
  const raw = [
    asff({ securityControlId: "EC2.13", complianceStatus: "FAILED", severityLabel: "HIGH", resourceIds: [SG], resourceTypes: ["AwsEc2SecurityGroup"], productName: "Security Hub" }),
    asff({ id: "p", securityControlId: "S3.8", complianceStatus: "PASSED", resourceIds: [BUCKET], resourceTypes: ["AwsS3Bucket"] }),
    asff({ id: "g", productName: "GuardDuty", title: "brute force", severityLabel: "MEDIUM", workflowStatus: "NEW", resourceIds: ["i-x"], resourceTypes: ["AwsEc2Instance"] }),
  ];
  const m = mapAsffFindings(raw, new Set([SG]));
  assert.deepEqual(m.coveredControls, ["EC2.13", "S3.8"]);
  assert.equal(m.findings.length, 2);
  const ec = m.findings.find((f) => f.ruleId === "securityhub.EC2.13")!;
  assert.equal(ec.nodeId, SG);
  assert.equal(ec.severity, "high");
  assert.equal(ec.source, "securityhub");
  assert.deepEqual(ec.controls, [{ framework: "fsbp", id: "EC2.13" }]);
  assert.equal(ec.resourceType, "aws::ec2::security-group");
  assert.equal(ec.evidence?.["complianceStatus"], "FAILED");
  const gd = m.findings.find((f) => f.ruleId === "securityhub.guardduty")!;
  assert.equal(gd.nodeId, undefined, "unknown resource → finding without nodeId");
  assert.deepEqual(gd.controls, []);
});

test("feeds off: meta has no feeds and native findings stand", async () => {
  const g = await discoverGraph(client());
  assert.equal(g.meta.feeds, undefined);
  assert.ok(g.findings.some((f) => f.kind === "public-resource" && f.source !== "accessanalyzer"));
  assert.ok(!g.findings.some((f) => f.source === "securityhub"));
});

test("Security Hub on: findings join the graph, covered controls recorded, unknown resources tolerated", async () => {
  const g = await discoverGraph(client({ hub: true }));
  parseGraph(g);
  assert.deepEqual(checkReferentialIntegrity(g), []);
  assert.deepEqual(g.meta.feeds, ["securityhub"]);
  assert.deepEqual(g.meta.securityHubControls, ["EC2.13", "EC2.14", "IAM.6"]);
  const sh = g.findings.filter((f) => f.source === "securityhub");
  assert.equal(sh.length, 3, "EC2.13 FAILED, IAM.6 FAILED, GuardDuty NEW; PASSED and RESOLVED excluded");
  assert.ok(sh.find((f) => f.ruleId === "securityhub.EC2.13")!.nodeId === SG);
  assert.ok(sh.find((f) => f.ruleId === "securityhub.IAM.6")!.nodeId === undefined);
  assert.ok(g.meta.capabilities?.includes("securityhub:findings"));
});

test("Access Analyzer on: supersedes native resource-policy findings and edges for covered resources", async () => {
  const g = await discoverGraph(client({ analyzer: true }));
  parseGraph(g);
  assert.deepEqual(checkReferentialIntegrity(g), []);
  const forBucket = g.findings.filter((f) => f.nodeId === BUCKET);
  assert.equal(forBucket.length, 1);
  assert.equal(forBucket[0]!.source, "accessanalyzer");
  assert.equal(forBucket[0]!.kind, "public-resource");
  assert.equal(forBucket[0]!.severity, "critical");
  assert.equal(forBucket[0]!.externalId, "aa-1");
  const edgesToBucket = g.edges.filter((e) => e.relationship === "can-access" && e.target === BUCKET);
  assert.equal(edgesToBucket.length, 1);
  assert.equal(edgesToBucket[0]!.attributes["source"], "accessanalyzer");
  // The role finding has no node in this graph: kept as a finding without nodeId, no edge.
  const role = g.findings.find((f) => f.externalId === "aa-2")!;
  assert.equal(role.kind, "external-can-access");
  assert.equal(role.severity, "medium", "conditioned → medium");
  assert.equal(role.nodeId, undefined);
  // Archived finding ignored.
  assert.ok(!g.findings.some((f) => f.externalId === "aa-3"));
  assert.deepEqual(g.meta.feeds, ["accessanalyzer"]);
});
