import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, type CloudNode, type Graph } from "@kumomiru/graph";
import { defaultRegistry, evaluate, controlStatuses } from "../src/index.js";

const ACCOUNT = "123456789012";
const CAPS = [
  "ec2:security-group", "ec2:instance", "ec2:network-acl", "ec2:launch-template", "elbv2:load-balancer", "ecs:cluster", "eks:cluster",
  "sqs:queue", "sns:topic", "dynamodb:table", "ecr:repository", "efs:file-system", "cloudfront:distribution", "apigateway:rest-api",
  "rds:db-snapshot", "rds:db-cluster",
];

function node(id: string, type: string, attributes: Record<string, unknown> = {}, name = id): CloudNode {
  return { id, type, name, account: ACCOUNT, region: "us-east-1", tags: {}, attributes };
}

function graph(): Graph {
  return parseGraph({
    nodes: [
      node("acl-open", "aws::ec2::network-acl", { entries: [{ ruleNumber: 100, egress: false, protocol: "-1", cidr: "0.0.0.0/0", action: "allow" }] }),
      node("acl-deny-first", "aws::ec2::network-acl", { entries: [
        { ruleNumber: 50, egress: false, protocol: "6", fromPort: 22, toPort: 22, cidr: "0.0.0.0/0", action: "deny" },
        { ruleNumber: 100, egress: false, protocol: "-1", cidr: "0.0.0.0/0", action: "allow" },
      ] }),
      node("sg-default-open", "aws::ec2::security-group", { ingress: [{ cidrs: ["10.0.0.0/8"], sourceGroupIds: [] }] }, "default"),
      node("sg-default-clean", "aws::ec2::security-group", { ingress: [] }, "default"),
      node("sg-app", "aws::ec2::security-group", { ingress: [{ cidrs: ["10.0.0.0/8"], sourceGroupIds: [] }] }, "app"),
      node("i-v1", "aws::ec2::instance", { imdsv2Required: false }),
      node("i-v2", "aws::ec2::instance", { imdsv2Required: true }),
      node("lt", "aws::ec2::launch-template", { imdsv2Required: false }),
      node("alb", "aws::elbv2::load-balancer", { lbType: "application", accessLogsEnabled: false, listeners: [{ port: 80, protocol: "HTTP", redirectsToHttps: false }] }),
      node("alb-ok", "aws::elbv2::load-balancer", { lbType: "application", accessLogsEnabled: true, listeners: [{ port: 80, protocol: "HTTP", redirectsToHttps: true }, { port: 443, protocol: "HTTPS", redirectsToHttps: false }] }),
      node("nlb", "aws::elbv2::load-balancer", { lbType: "network", listeners: [{ port: 443, protocol: "TLS", redirectsToHttps: false }] }),
      node("svc", "aws::ecs::service", { assignPublicIp: true }),
      node("eks", "aws::eks::cluster", { endpointPublicAccess: true, publicAccessCidrs: ["0.0.0.0/0"], loggingEnabled: false }),
      node("eks-ok", "aws::eks::cluster", { endpointPublicAccess: true, publicAccessCidrs: ["203.0.113.0/24"], loggingEnabled: true }),
      node("q", "aws::sqs::queue", { kmsEncrypted: false }),
      node("t", "aws::sns::topic", { kmsEncrypted: false }),
      node("ddb", "aws::dynamodb::table", { pitrEnabled: false }),
      node("repo", "aws::ecr::repository", { scanOnPush: false, tagImmutability: false, lifecyclePolicy: false }),
      node("fs", "aws::efs::file-system", { encrypted: false }),
      node("cf", "aws::cloudfront::distribution", { enabled: true, viewerProtocolPolicy: "allow-all", loggingEnabled: false }),
      node("cf-off", "aws::cloudfront::distribution", { enabled: false, viewerProtocolPolicy: "allow-all", loggingEnabled: false }),
      node("api", "aws::apigateway::rest-api", { stages: [{ name: "prod", loggingEnabled: false }] }),
      node("snap", "aws::rds::db-snapshot", { public: true, encrypted: false }),
      node("cluster", "aws::rds::db-cluster", { storageEncrypted: false }),
    ],
    edges: [],
    findings: [],
    meta: { generatedAt: "2026-09-19T00:00:00Z", source: "aws-live", provider: "aws" },
  });
}

test("tranche B rules: offenders fail, clean resources pass or skip", () => {
  const ev = evaluate(graph(), defaultRegistry(), { capabilities: CAPS });
  const st = (rule: string, id: string) => ev.results.find((r) => r.ruleId === rule && r.resourceId === id)?.status;

  assert.equal(st("ec2.nacl-unrestricted-admin-ports", "acl-open"), "fail");
  assert.equal(st("ec2.nacl-unrestricted-admin-ports", "acl-deny-first"), "fail", "22 denied first, but 3389 still allowed by the catch-all");
  assert.equal(st("ec2.default-sg-restricts-traffic", "sg-default-open"), "fail");
  assert.equal(st("ec2.default-sg-restricts-traffic", "sg-default-clean"), "pass");
  assert.equal(st("ec2.default-sg-restricts-traffic", "sg-app"), "not-applicable");
  assert.equal(st("ec2.instance-imdsv2", "i-v1"), "fail");
  assert.equal(st("ec2.instance-imdsv2", "i-v2"), "pass");
  assert.equal(st("ec2.launch-template-imdsv2", "lt"), "fail");
  assert.equal(st("elbv2.alb-http-redirects-to-https", "alb"), "fail");
  assert.equal(st("elbv2.alb-http-redirects-to-https", "alb-ok"), "pass");
  assert.equal(st("elbv2.alb-http-redirects-to-https", "nlb"), "not-applicable");
  assert.equal(st("elbv2.alb-access-logging", "alb"), "fail");
  assert.equal(st("elbv2.alb-access-logging", "nlb"), "not-applicable");
  assert.equal(st("ecs.service-public-ip", "svc"), "fail");
  assert.equal(st("eks.public-endpoint", "eks"), "fail");
  assert.equal(st("eks.public-endpoint", "eks-ok"), "pass");
  assert.equal(st("eks.control-plane-logging", "eks"), "fail");
  assert.equal(st("sqs.queue-encrypted", "q"), "fail");
  assert.equal(st("sns.topic-encrypted", "t"), "fail");
  assert.equal(st("dynamodb.pitr-enabled", "ddb"), "fail");
  assert.equal(st("ecr.scan-on-push", "repo"), "fail");
  assert.equal(st("ecr.tag-immutability", "repo"), "fail");
  assert.equal(st("ecr.lifecycle-policy", "repo"), "fail");
  assert.equal(st("efs.file-system-encrypted", "fs"), "fail");
  assert.equal(st("cloudfront.viewer-protocol-https", "cf"), "fail");
  assert.equal(st("cloudfront.viewer-protocol-https", "cf-off"), "not-applicable");
  assert.equal(st("cloudfront.access-logging", "cf"), "fail");
  assert.equal(st("apigateway.stage-logging", "api"), "fail");
  assert.equal(st("rds.snapshot-public", "snap"), "fail");
  assert.equal(st("rds.cluster-storage-encrypted", "cluster"), "fail");

  const reg = defaultRegistry();
  const byId = new Map(controlStatuses("fsbp", ev.results, reg).map((c) => [c.controlId, c]));
  for (const id of ["EC2.2", "EC2.8", "EC2.21", "AutoScaling.3", "ELB.1", "ELB.5", "ECS.2", "EKS.1", "EKS.8", "SQS.1", "SNS.1", "DynamoDB.2", "ECR.1", "ECR.2", "ECR.3", "EFS.1", "CloudFront.3", "CloudFront.5", "APIGateway.1", "RDS.1", "RDS.27"]) {
    assert.equal(byId.get(id)?.status, "fail", id);
  }
  assert.ok(reg.list().length >= 51, `rules: ${reg.list().length}`);
});
