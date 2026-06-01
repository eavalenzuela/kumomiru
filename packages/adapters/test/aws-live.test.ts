import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, checkReferentialIntegrity } from "@kumomiru/graph";
import {
  runLiveDiscovery,
  discoverGraph,
  CredentialBroker,
  type DiscoveryClient,
  type AwsCredentials,
} from "../src/index.js";

const ACCOUNT = "123456789012";
const REGION = "us-east-1";

/** A fake read-only discovery client with a small but representative account. */
function fakeClient(): DiscoveryClient {
  return {
    accountId: async () => ACCOUNT,
    region: () => REGION,
    vpcs: async () => [
      { vpcId: "vpc-1", cidrBlock: "10.0.0.0/16", tags: { Name: "main-vpc" } },
    ],
    subnets: async () => [
      {
        subnetId: "subnet-pub",
        vpcId: "vpc-1",
        cidrBlock: "10.0.1.0/24",
        mapPublicIpOnLaunch: true,
        tags: { Name: "public-1a" },
      },
    ],
    internetGateways: async () => [
      { internetGatewayId: "igw-1", attachedVpcId: "vpc-1", tags: {} },
    ],
    securityGroups: async () => [
      {
        groupId: "sg-web",
        groupName: "web-sg",
        vpcId: "vpc-1",
        ingress: [
          { fromPort: 443, toPort: 443, ipProtocol: "tcp", cidrs: ["0.0.0.0/0"] },
        ],
        tags: {},
      },
    ],
    instances: async () => [
      {
        instanceId: "i-web",
        subnetId: "subnet-pub",
        instanceType: "t3.small",
        publicIp: "203.0.113.10",
        securityGroupIds: ["sg-web"],
        // Hard-coded key in user-data — must be detected and redacted.
        userData:
          "#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        tags: { Name: "web-server" },
      },
    ],
    dbInstances: async () => [
      {
        dbInstanceIdentifier: "app-postgres",
        engine: "postgres",
        port: 5432,
        publiclyAccessible: false,
        subnetIds: ["subnet-pub"],
        tags: {},
      },
    ],
    functions: async () => [
      {
        functionName: "report-generator",
        runtime: "nodejs20.x",
        environment: { LOG_LEVEL: "info" },
        tags: {},
      },
    ],
    secrets: async () => [
      {
        arn: `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:db-credentials-AbCdEf`,
        name: "db-credentials",
        tags: {},
      },
    ],
    roles: async () => [
      {
        roleName: "OrganizationAdmin",
        arn: `arn:aws:iam::${ACCOUNT}:role/OrganizationAdmin`,
        trustedPrincipals: [
          { type: "aws", value: "arn:aws:iam::999988887777:root" },
        ],
        tags: {},
      },
    ],
  };
}

test("discovers a schema-valid, referentially-intact graph", async () => {
  const graph = await discoverGraph(fakeClient());
  parseGraph(graph);
  assert.deepEqual(checkReferentialIntegrity(graph), []);
  assert.equal(graph.meta.source, "aws-live");
});

test("never stores a resolved secret value; secrets become markers", async () => {
  const graph = await discoverGraph(fakeClient());
  const json = JSON.stringify(graph);
  // The literal key from user-data must not appear anywhere in the graph.
  assert.ok(
    !json.includes("AKIAIOSFODNN7EXAMPLE"),
    "raw secret leaked into graph",
  );
  // Secrets Manager secret is listed but not resolved.
  const secret = graph.nodes.find(
    (n) => n.type === "aws::secretsmanager::secret",
  )!;
  assert.equal(secret.attributes["valueResolved"], false);
});

test("raises a plaintext-secret finding for user-data", async () => {
  const graph = await discoverGraph(fakeClient());
  const f = graph.findings.find((f) => f.kind === "plaintext-secret");
  assert.ok(f, "expected a plaintext-secret finding");
  assert.equal(f!.severity, "high");
});

test("flags internet-facing ingress on the network lens", async () => {
  const graph = await discoverGraph(fakeClient());
  const exposed = graph.edges.find(
    (e) => e.attributes["internetFacing"] === true,
  );
  assert.ok(exposed, "expected an internet-facing edge");
  assert.equal(exposed!.lens, "network");
});

test("raises a critical finding + iam edge for external assume-role", async () => {
  const graph = await discoverGraph(fakeClient());
  const ext = graph.findings.find((f) => f.kind === "external-can-assume");
  assert.ok(ext, "expected external-can-assume finding");
  assert.equal(ext!.severity, "critical");
  const edge = graph.edges.find(
    (e) => e.relationship === "can-assume" && e.attributes["external"] === true,
  );
  assert.ok(edge, "expected an external can-assume edge");
  assert.equal(edge!.lens, "iam");
});

test("runLiveDiscovery scrubs credentials after the run", async () => {
  const creds: AwsCredentials = {
    accessKeyId: "AKIAEXAMPLE",
    secretAccessKey: "secret",
    sessionToken: "token",
    region: REGION,
  };
  let captured: AwsCredentials | null = null;
  const graph = await runLiveDiscovery(creds, (borrowed) => {
    captured = borrowed;
    return fakeClient();
  });
  assert.ok(graph.nodes.length > 0);
  // The broker overwrites the credential object's secret fields after the run.
  assert.equal(captured!.accessKeyId, "");
  assert.equal(captured!.secretAccessKey, "");
});

test("a spent broker refuses reuse", async () => {
  const broker = new CredentialBroker({
    accessKeyId: "a",
    secretAccessKey: "b",
    region: REGION,
  });
  await broker.use(async () => "ok");
  await assert.rejects(() => broker.use(async () => "again"));
});
