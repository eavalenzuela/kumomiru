import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, checkReferentialIntegrity } from "@kumomiru/graph";
import {
  runLiveDiscovery,
  discoverGraph,
  mergeGraphs,
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
      {
        groupId: "sg-db",
        groupName: "db-sg",
        vpcId: "vpc-1",
        // The db tier allows Postgres only from the web tier (SG-to-SG rule):
        // the explicit "what talks to what" signal for the dataflow lens.
        ingress: [
          {
            fromPort: 5432,
            toPort: 5432,
            ipProtocol: "tcp",
            cidrs: [],
            sourceGroupIds: ["sg-web"],
          },
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
      {
        instanceId: "i-db",
        subnetId: "subnet-pub",
        instanceType: "t3.small",
        securityGroupIds: ["sg-db"],
        tags: { Name: "db-host" },
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
        // An explicit ARN reference to the secret: a dataflow edge, but the
        // value is never stored on the graph.
        environment: {
          LOG_LEVEL: "info",
          DB_SECRET_ARN: `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:db-credentials-AbCdEf`,
        },
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

test("infers SG-to-SG dataflow: web tier talks to db tier on its port", async () => {
  const graph = await discoverGraph(fakeClient());
  const flow = graph.edges.find(
    (e) =>
      e.lens === "dataflow" &&
      e.relationship === "talks-to" &&
      e.attributes["ports"] === "5432",
  );
  assert.ok(flow, "expected an SG-derived dataflow edge");
  const web = graph.nodes.find((n) => n.name === "web-server")!;
  const dbHost = graph.nodes.find((n) => n.name === "db-host")!;
  assert.equal(flow!.source, web.id);
  assert.equal(flow!.target, dbHost.id);
});

test("infers Lambda->secret dataflow from an explicit env ARN reference", async () => {
  const graph = await discoverGraph(fakeClient());
  const secret = graph.nodes.find(
    (n) => n.type === "aws::secretsmanager::secret",
  )!;
  const ref = graph.edges.find(
    (e) =>
      e.lens === "dataflow" &&
      e.target === secret.id &&
      e.attributes["via"] === "lambda-env",
  );
  assert.ok(ref, "expected a Lambda->secret dataflow reference edge");
  assert.equal(ref!.relationship, "reads-from");
});

test("internet-facing ingress edge sources from the SG, never a self-loop", async () => {
  const graph = await discoverGraph(fakeClient());
  const exposed = graph.edges.find(
    (e) => e.attributes["internetFacing"] === true,
  )!;
  assert.notEqual(exposed.source, exposed.target, "must not be a self-loop");
  const src = graph.nodes.find((n) => n.id === exposed.source)!;
  assert.equal(src.type, "aws::ec2::security-group");
  assert.equal(exposed.attributes["from"], "0.0.0.0/0");
});

test("scans tags for secrets and redacts them in place (parity with terraform)", async () => {
  const base = fakeClient();
  const client: DiscoveryClient = {
    ...base,
    vpcs: async () => [
      {
        vpcId: "vpc-1",
        cidrBlock: "10.0.0.0/16",
        tags: { Name: "main-vpc", DB_PASSWORD: "hunter2supersecret" },
      },
    ],
  };
  const graph = await discoverGraph(client);
  const json = JSON.stringify(graph);
  assert.ok(!json.includes("hunter2supersecret"), "tag secret leaked");
  assert.ok(
    graph.findings.some(
      (f) => f.kind === "plaintext-secret" && f.title.includes("tags"),
    ),
    "expected a tag plaintext-secret finding",
  );
  const vpc = graph.nodes.find((n) => n.type === "aws::ec2::vpc")!;
  assert.equal(vpc.tags["DB_PASSWORD"], "[redacted-secret]");
});

test("Lambda-env dataflow ignores a substring hit but matches a delimited name", async () => {
  const base = fakeClient();
  const client: DiscoveryClient = {
    ...base,
    dbInstances: async () => [
      {
        dbInstanceIdentifier: "prod",
        engine: "postgres",
        port: 5432,
        publiclyAccessible: false,
        subnetIds: [],
        tags: {},
      },
    ],
    functions: async () => [
      {
        functionName: "substr",
        runtime: "nodejs20.x",
        environment: { MODE: "production-config" },
        tags: {},
      },
      {
        functionName: "delim",
        runtime: "nodejs20.x",
        environment: { DB_HOST: "prod.internal.example" },
        tags: {},
      },
    ],
  };
  const graph = await discoverGraph(client);
  const dbNode = graph.nodes.find(
    (n) => n.type === "aws::rds::db-instance" && n.name === "prod",
  )!;
  const substrFn = graph.nodes.find((n) => n.name === "substr")!;
  const delimFn = graph.nodes.find((n) => n.name === "delim")!;
  const flowFrom = (fnId: string) =>
    graph.edges.some(
      (e) => e.lens === "dataflow" && e.source === fnId && e.target === dbNode.id,
    );
  assert.ok(!flowFrom(substrFn.id), "substring-only match must not draw an edge");
  assert.ok(flowFrom(delimFn.id), "delimited name match must draw an edge");
});

test("meta.generatedAt is the injected clock, not the epoch", async () => {
  const fixed = new Date("2026-09-19T12:00:00.000Z");
  const graph = await discoverGraph(fakeClient(), { now: () => fixed });
  assert.equal(graph.meta.generatedAt, fixed.toISOString());
  // Default clock is "now", never 1970.
  const live = await discoverGraph(fakeClient());
  assert.ok(new Date(live.meta.generatedAt).getFullYear() >= 2026);
});

test("node ids carry the client's partition; default is commercial aws", async () => {
  const gov = await discoverGraph({
    ...fakeClient(),
    partition: async () => "aws-us-gov",
  });
  const vpc = gov.nodes.find((n) => n.type === "aws::ec2::vpc")!;
  assert.ok(vpc.id.startsWith("arn:aws-us-gov:ec2:"), vpc.id);
  // Ids the adapter synthesizes (EC2/RDS/Lambda) must follow the partition.
  // ARNs the cloud returns verbatim (roles, secrets) are passed through as-is.
  const synthesized = new Set([
    "aws::ec2::vpc",
    "aws::ec2::subnet",
    "aws::ec2::internet-gateway",
    "aws::ec2::security-group",
    "aws::ec2::instance",
    "aws::rds::db-instance",
    "aws::lambda::function",
  ]);
  for (const n of gov.nodes.filter((n) => synthesized.has(n.type))) {
    assert.ok(n.id.startsWith("arn:aws-us-gov:"), `${n.type} ${n.id}`);
  }
  assert.deepEqual(checkReferentialIntegrity(gov), []);

  const commercial = await discoverGraph(fakeClient());
  const vpc2 = commercial.nodes.find((n) => n.type === "aws::ec2::vpc")!;
  assert.ok(vpc2.id.startsWith("arn:aws:ec2:"), vpc2.id);
});

test("scope: regional collects resources but no IAM; global collects IAM only", async () => {
  const regional = await discoverGraph(fakeClient(), { scope: "regional" });
  assert.ok(regional.nodes.some((n) => n.type === "aws::ec2::instance"));
  assert.ok(!regional.nodes.some((n) => n.type === "aws::iam::role"));
  assert.ok(!regional.edges.some((e) => e.lens === "iam"));
  assert.ok(!regional.findings.some((f) => f.kind === "external-can-assume"));
  assert.deepEqual(checkReferentialIntegrity(regional), []);

  const global = await discoverGraph(fakeClient(), { scope: "global" });
  assert.ok(global.nodes.some((n) => n.type === "aws::iam::role"));
  assert.ok(global.edges.some((e) => e.lens === "iam"));
  assert.ok(global.findings.some((f) => f.kind === "external-can-assume"));
  assert.ok(!global.nodes.some((n) => n.type === "aws::ec2::instance"));
  // No empty region container is synthesized for a global-only pass.
  assert.ok(!global.nodes.some((n) => n.type === "aws::region"));
  assert.deepEqual(checkReferentialIntegrity(global), []);
});

test("mergeGraphs(global + regional...) equals a full single-region discovery", async () => {
  const full = await discoverGraph(fakeClient());
  const global = await discoverGraph(fakeClient(), { scope: "global" });
  const regional = await discoverGraph(fakeClient(), { scope: "regional" });
  const merged = mergeGraphs([global, regional], {
    generatedAt: full.meta.generatedAt,
    source: "aws-live",
    accountId: ACCOUNT,
    regions: [REGION],
  });
  const ids = (g: { nodes: { id: string }[] }) => g.nodes.map((n) => n.id).sort();
  assert.deepEqual(ids(merged), ids(full));
  assert.equal(merged.edges.length, full.edges.length);
  assert.equal(merged.findings.length, full.findings.length);
  assert.deepEqual(checkReferentialIntegrity(merged), []);
  assert.deepEqual(merged.meta.regions, [REGION]);
  parseGraph(merged);

  // Two regions share one account node; merging must not duplicate it.
  const second = { ...fakeClient(), region: () => "eu-west-1" };
  const regional2 = await discoverGraph(second, { scope: "regional" });
  const two = mergeGraphs([global, regional, regional2], {
    generatedAt: full.meta.generatedAt,
    source: "aws-live",
  });
  assert.equal(two.nodes.filter((n) => n.type === "aws::account").length, 1);
  assert.equal(two.nodes.filter((n) => n.type === "aws::region").length, 2);
  assert.deepEqual(checkReferentialIntegrity(two), []);
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
