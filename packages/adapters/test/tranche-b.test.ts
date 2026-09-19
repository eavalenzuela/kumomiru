import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, checkReferentialIntegrity } from "@kumomiru/graph";
import { discoverGraph, terraformAdapter, projectPolicyDocument, type DiscoveryClient } from "../src/index.js";

const ACCOUNT = "123456789012";
const REGION = "us-east-1";
const LB = `arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:loadbalancer/app/web/abc`;
const NLB = `arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:loadbalancer/net/edge/def`;
const BUCKET = "arn:aws:s3:::assets";

function client(): DiscoveryClient {
  return {
    accountId: async () => ACCOUNT,
    region: () => REGION,
    vpcs: async () => [{ vpcId: "vpc-1", tags: {} }],
    subnets: async () => [
      { subnetId: "subnet-pub", vpcId: "vpc-1", tags: {} },
      { subnetId: "subnet-priv", vpcId: "vpc-1", tags: {} },
      { subnetId: "subnet-orphan", vpcId: "vpc-1", tags: {} },
    ],
    internetGateways: async () => [{ internetGatewayId: "igw-1", attachedVpcId: "vpc-1", tags: {} }],
    securityGroups: async () => [
      { groupId: "sg-web", vpcId: "vpc-1", ingress: [{ fromPort: 443, toPort: 443, ipProtocol: "tcp", cidrs: ["0.0.0.0/0"] }], tags: {} },
      { groupId: "sg-app", vpcId: "vpc-1", ingress: [], tags: {} },
    ],
    instances: async () => [
      { instanceId: "i-1", subnetId: "subnet-priv", securityGroupIds: ["sg-app"], imdsv2Required: false, tags: {} },
      { instanceId: "i-2", subnetId: "subnet-priv", securityGroupIds: ["sg-app"], imdsv2Required: true, tags: {} },
    ],
    dbInstances: async () => [{ dbInstanceIdentifier: "db-a", subnetIds: ["subnet-priv"], tags: {} }],
    functions: async () => [{ functionName: "fn", environment: {}, tags: {} }],
    secrets: async () => [],
    roles: async () => [],
    s3Buckets: async () => [{ name: "assets", arn: BUCKET, region: REGION, tags: {} }],
    routeTables: async () => [
      { routeTableId: "rtb-main", vpcId: "vpc-1", subnetIds: [], main: true, routes: [{ destination: "10.0.0.0/16", targetType: "local" }], tags: {} },
      { routeTableId: "rtb-pub", vpcId: "vpc-1", subnetIds: ["subnet-pub"], main: false, routes: [{ destination: "0.0.0.0/0", targetType: "igw", targetId: "igw-1" }], tags: {} },
      { routeTableId: "rtb-priv", vpcId: "vpc-1", subnetIds: ["subnet-priv"], main: false, routes: [{ destination: "0.0.0.0/0", targetType: "nat", targetId: "nat-1" }], tags: {} },
    ],
    natGateways: async () => [{ natGatewayId: "nat-1", vpcId: "vpc-1", subnetId: "subnet-pub", tags: {} }],
    vpcPeerings: async () => [{ peeringId: "pcx-1", requesterVpcId: "vpc-1", requesterAccount: ACCOUNT, accepterVpcId: "vpc-other", accepterAccount: "999988887777", status: "active", tags: {} }],
    vpcEndpoints: async () => [{ endpointId: "vpce-1", vpcId: "vpc-1", serviceName: "com.amazonaws.us-east-1.s3", type: "Gateway", tags: {} }],
    networkAcls: async () => [
      { aclId: "acl-1", vpcId: "vpc-1", subnetIds: ["subnet-pub"], isDefault: true, entries: [{ ruleNumber: 100, egress: false, protocol: "-1", cidr: "0.0.0.0/0", action: "allow" }], tags: {} },
    ],
    loadBalancers: async () => [
      {
        arn: LB, name: "web", type: "application", scheme: "internet-facing", vpcId: "vpc-1", subnetIds: ["subnet-pub"], securityGroupIds: ["sg-web"],
        accessLogsEnabled: false,
        listeners: [{ port: 80, protocol: "HTTP", redirectsToHttps: false }, { port: 443, protocol: "HTTPS", redirectsToHttps: false }],
        targets: [{ targetGroupArn: "tg", targetType: "instance", id: "i-1", port: 8080 }, { targetGroupArn: "tg", targetType: "instance", id: "i-missing" }],
        tags: {},
      },
      { arn: NLB, name: "edge", type: "network", scheme: "internet-facing", vpcId: "vpc-1", subnetIds: ["subnet-pub"], securityGroupIds: [], listeners: [{ port: 443, protocol: "TLS", redirectsToHttps: false }], targets: [], tags: {} },
    ],
    ecsTaskDefinitions: async () => [
      { arn: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/api:3`, family: "api", containers: [{ name: "api", environment: { DB_PASSWORD: "hunter2supersecret" } }], tags: {} },
    ],
    ecsClusters: async () => [
      {
        arn: `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/main`, name: "main", tags: {},
        services: [{ arn: `arn:aws:ecs:${REGION}:${ACCOUNT}:service/main/api`, name: "api", taskDefinitionArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/api:3`, assignPublicIp: true, subnetIds: ["subnet-pub"], securityGroupIds: ["sg-web"], launchType: "FARGATE" }],
      },
    ],
    eksClusters: async () => [
      { arn: `arn:aws:eks:${REGION}:${ACCOUNT}:cluster/k8s`, name: "k8s", vpcId: "vpc-1", subnetIds: [], securityGroupIds: ["sg-app"], endpointPublicAccess: true, endpointPrivateAccess: false, publicAccessCidrs: ["0.0.0.0/0"], loggingEnabled: false, tags: {} },
    ],
    sqsQueues: async () => [
      { arn: `arn:aws:sqs:${REGION}:${ACCOUNT}:jobs`, name: "jobs", kmsEncrypted: false, tags: {}, policyStatements: projectPolicyDocument({ Statement: [{ Effect: "Allow", Principal: "*", Action: "sqs:SendMessage", Resource: "*" }] }) },
    ],
    snsTopics: async () => [{ arn: `arn:aws:sns:${REGION}:${ACCOUNT}:alerts`, name: "alerts", kmsEncrypted: true, tags: {} }],
    dynamoTables: async () => [{ arn: `arn:aws:dynamodb:${REGION}:${ACCOUNT}:table/orders`, name: "orders", pitrEnabled: false, tags: {} }],
    ecrRepositories: async () => [{ arn: `arn:aws:ecr:${REGION}:${ACCOUNT}:repository/api`, name: "api", scanOnPush: false, tagImmutability: false, lifecyclePolicy: false, tags: {} }],
    launchTemplates: async () => [{ launchTemplateId: "lt-1", name: "web-lt", userData: "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", imdsv2Required: false, tags: {} }],
    autoScalingGroups: async () => [{ arn: `arn:aws:autoscaling:${REGION}:${ACCOUNT}:autoScalingGroup:uuid:autoScalingGroupName/web-asg`, name: "web-asg", launchTemplateId: "lt-1", instanceIds: ["i-1", "i-2"], subnetIds: ["subnet-priv"], tags: {} }],
    fileSystems: async () => [{ arn: `arn:aws:elasticfilesystem:${REGION}:${ACCOUNT}:file-system/fs-1`, fileSystemId: "fs-1", encrypted: false, tags: {} }],
    cloudFrontDistributions: async () => [
      { arn: `arn:aws:cloudfront::${ACCOUNT}:distribution/E1`, id: "E1", domainName: "d1.cloudfront.net", enabled: true, viewerProtocolPolicy: "allow-all", loggingEnabled: false, origins: [{ id: "s3", domainName: "assets.s3.us-east-1.amazonaws.com", type: "s3" }], tags: {} },
    ],
    restApis: async () => [{ id: "abc", arn: `arn:aws:apigateway:${REGION}::/restapis/abc`, name: "public-api", stages: [{ name: "prod", loggingEnabled: false, tracingEnabled: false }], tags: {} }],
    dbClusters: async () => [{ arn: `arn:aws:rds:${REGION}:${ACCOUNT}:cluster:aurora`, identifier: "aurora", engine: "aurora-postgresql", storageEncrypted: true, memberInstanceIdentifiers: ["db-a"], tags: {} }],
    dbSnapshots: async () => [{ arn: `arn:aws:rds:${REGION}:${ACCOUNT}:snapshot:snap-1`, identifier: "snap-1", kind: "instance", encrypted: false, public: true, tags: {} }],
    ssmParameters: async () => [{ arn: `arn:aws:ssm:${REGION}:${ACCOUNT}:parameter/db/pass`, name: "/db/pass", type: "SecureString" }],
  };
}

test("tranche B: nodes, edges, and posture attributes across the new collectors", async () => {
  const g = await discoverGraph(client());
  parseGraph(g);
  assert.deepEqual(checkReferentialIntegrity(g), []);
  const byType = (t: string) => g.nodes.filter((n) => n.type === t);
  const node = (id: string) => g.nodes.find((n) => n.id === id)!;

  // Routing: subnet-pub is public via its own table; subnet-orphan inherits the main table (no IGW) → not public.
  const subnetId = (raw: string) => `arn:aws:ec2:${REGION}:${ACCOUNT}:subnet/${raw}`;
  assert.equal(node(subnetId("subnet-pub")).attributes["public"], true);
  assert.equal(node(subnetId("subnet-priv")).attributes["public"], false);
  assert.equal(node(subnetId("subnet-orphan")).attributes["public"], false);
  assert.ok(g.edges.some((e) => e.relationship === "routes-to" && e.target === `arn:aws:ec2:${REGION}:${ACCOUNT}:internet-gateway/igw-1`));
  assert.ok(g.edges.some((e) => e.relationship === "routes-to" && e.target === `arn:aws:ec2:${REGION}:${ACCOUNT}:natgateway/nat-1`));
  assert.equal(byType("aws::ec2::vpc-peering")[0]!.attributes["crossAccount"], true);
  assert.equal(byType("aws::ec2::vpc-endpoint")[0]!.name, "s3");
  assert.ok(g.edges.some((e) => e.relationship === "protects" && e.source.includes("network-acl/acl-1")));

  // Load balancers: ALB gets the red edge from its open SG and targets i-1 only; NLB gets an IGW edge.
  const alb = node(LB);
  assert.equal(alb.attributes["internetFacing"], true);
  assert.ok(g.edges.some((e) => e.relationship === "allows-ingress" && e.target === LB && e.attributes["internetFacing"] === true));
  const targets = g.edges.filter((e) => e.relationship === "targets" && e.source === LB);
  assert.equal(targets.length, 1, "missing instance target is skipped");
  assert.equal(targets[0]!.attributes["port"], 8080);
  assert.ok(g.edges.some((e) => e.relationship === "allows-ingress" && e.target === NLB && e.source.includes("internet-gateway")));

  // Containers: task-def env secret redacted + finding; public-IP service gets the red edge; EKS attributes.
  const td = byType("aws::ecs::task-definition")[0]!;
  assert.ok(td.attributes["environmentSecret"]);
  assert.ok(!JSON.stringify(g).includes("hunter2supersecret"));
  assert.ok(g.findings.some((f) => f.kind === "plaintext-secret" && f.nodeId === td.id));
  assert.ok(g.edges.some((e) => e.relationship === "runs" && e.target === td.id));
  assert.ok(g.edges.some((e) => e.relationship === "allows-ingress" && e.target.endsWith("service/main/api")));
  assert.equal(byType("aws::eks::cluster")[0]!.attributes["endpointPublicAccess"], true);

  // Messaging + data + scaling + edge.
  assert.ok(g.findings.some((f) => f.kind === "public-resource" && f.nodeId?.endsWith(":jobs")), "public SQS policy");
  assert.equal(byType("aws::dynamodb::table")[0]!.attributes["pitrEnabled"], false);
  assert.equal(byType("aws::ecr::repository")[0]!.attributes["scanOnPush"], false);
  const lt = byType("aws::ec2::launch-template")[0]!;
  assert.ok(lt.attributes["userDataSecret"]);
  assert.ok(!JSON.stringify(g).includes("wJalrXUtnFEMI"));
  assert.ok(g.edges.some((e) => e.relationship === "uses" && e.target === lt.id));
  assert.equal(g.edges.filter((e) => e.relationship === "manages").length, 2);
  assert.equal(byType("aws::efs::file-system")[0]!.attributes["encrypted"], false);
  const cf = byType("aws::cloudfront::distribution")[0]!;
  assert.equal(cf.attributes["viewerProtocolPolicy"], "allow-all");
  assert.ok(g.edges.some((e) => e.source === cf.id && e.target === BUCKET && e.relationship === "reads-from"), "CloudFront → bucket origin in an all-scope run");
  assert.equal(byType("aws::apigateway::rest-api")[0]!.attributes["internetFacing"], true);
  assert.ok(g.edges.some((e) => e.relationship === "contains" && e.source.endsWith("cluster:aurora")));
  assert.equal(byType("aws::rds::db-snapshot")[0]!.attributes["public"], true);
  assert.equal(byType("aws::ssm::parameter")[0]!.attributes["secretPresent"], true);
  assert.equal(node(`arn:aws:ec2:${REGION}:${ACCOUNT}:instance/i-1`).attributes["imdsv2Required"], false);

  for (const c of ["ec2:route-table", "elbv2:load-balancer", "ecs:cluster", "eks:cluster", "sqs:queue", "cloudfront:distribution", "rds:db-snapshot", "ssm:parameter"]) {
    assert.ok(g.meta.capabilities?.includes(c), c);
  }
  // CloudFront is global: absent from a regional-only pass, present in a global one.
  const regional = await discoverGraph(client(), { scope: "regional" });
  assert.ok(!regional.meta.capabilities?.includes("cloudfront:distribution"));
  const global = await discoverGraph(client(), { scope: "global" });
  assert.ok(global.nodes.some((n) => n.type === "aws::cloudfront::distribution"));
  assert.deepEqual(checkReferentialIntegrity(global), []);
});

test("terraform: aws_s3_bucket_policy joins its bucket and feeds the resource-access pass", () => {
  const state = {
    version: 4,
    resources: [
      { mode: "managed", type: "aws_s3_bucket", name: "logs", instances: [{ attributes: { id: "corp-logs", bucket: "corp-logs", arn: "arn:aws:s3:::corp-logs", region: "us-east-1" } }] },
      {
        mode: "managed", type: "aws_s3_bucket_policy", name: "logs",
        instances: [{ attributes: { bucket: "corp-logs", policy: JSON.stringify({ Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::corp-logs/*" }] }) } }],
      },
      { mode: "managed", type: "aws_iam_role", name: "r", instances: [{ attributes: { name: "r", arn: "arn:aws:iam::123456789012:role/r", assume_role_policy: JSON.stringify({ Statement: [] }) } }] },
    ],
  };
  const g = terraformAdapter.toGraph(state);
  parseGraph(g);
  assert.deepEqual(checkReferentialIntegrity(g), []);
  const bucket = g.nodes.find((n) => n.type === "aws::s3::bucket")!;
  assert.equal((bucket.attributes["policyStatements"] as unknown[]).length, 1);
  assert.ok(g.findings.some((f) => f.kind === "public-resource" && f.nodeId === bucket.id));
  assert.ok(g.edges.some((e) => e.relationship === "can-access" && e.target === bucket.id));
  assert.ok(g.meta.capabilities?.includes("s3:bucket"));
  assert.ok(new Date(g.meta.generatedAt).getFullYear() >= 2026, "no more epoch timestamps");
});
