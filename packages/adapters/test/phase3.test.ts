import { test } from "node:test";
import assert from "node:assert/strict";

import { parseGraph, checkReferentialIntegrity, redactGraph } from "@kumomiru/graph";
import {
  discoverGraph,
  mergeGraphs,
  analyzeResourceAccess,
  projectPolicyDocument,
  type DiscoveryClient,
  type AnalyzedPrincipal,
} from "../src/index.js";

const ACCOUNT = "123456789012";
const REGION = "us-east-1";
const BUCKET = `arn:aws:s3:::data-bucket`;
const KEY = `arn:aws:kms:${REGION}:${ACCOUNT}:key/1111-2222`;
const ROLE = `arn:aws:iam::${ACCOUNT}:role/Reader`;
const USER = `arn:aws:iam::${ACCOUNT}:user/alice`;

/** A client that implements every optional Phase 3 collector. */
function richClient(): DiscoveryClient {
  return {
    accountId: async () => ACCOUNT,
    region: () => REGION,
    capabilities: () => ["lambda:policy", "secretsmanager:policy", "ec2:flow-log", "rds:encryption"],
    vpcs: async () => [{ vpcId: "vpc-1", cidrBlock: "10.0.0.0/16", flowLogsEnabled: false, tags: {} }],
    subnets: async () => [{ subnetId: "subnet-1", vpcId: "vpc-1", tags: {} }],
    internetGateways: async () => [],
    securityGroups: async () => [{ groupId: "sg-1", vpcId: "vpc-1", ingress: [], tags: {} }],
    instances: async () => [{ instanceId: "i-1", subnetId: "subnet-1", securityGroupIds: ["sg-1"], tags: {} }],
    dbInstances: async () => [
      { dbInstanceIdentifier: "db-1", engine: "postgres", publiclyAccessible: false, storageEncrypted: false, subnetIds: ["subnet-1"], tags: {} },
    ],
    functions: async () => [
      {
        functionName: "public-fn",
        environment: {},
        urlAuthTypes: ["NONE"],
        resourcePolicy: projectPolicyDocument({
          Statement: [{ Effect: "Allow", Principal: "*", Action: "lambda:InvokeFunctionUrl", Resource: "*" }],
        }),
        tags: {},
      },
    ],
    secrets: async () => [
      {
        arn: `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:db-AbCdEf`,
        name: "db",
        rotationEnabled: false,
        resourcePolicy: projectPolicyDocument({
          Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::999988887777:role/Partner" }, Action: "secretsmanager:GetSecretValue", Resource: "*" }],
        }),
        tags: {},
      },
    ],
    roles: async () => [
      {
        roleName: "Reader",
        arn: ROLE,
        trustedPrincipals: [{ type: "service", value: "ec2.amazonaws.com" }],
        identityStatements: [{ effect: "Allow", actions: ["s3:GetObject"], resources: [`${BUCKET}/*`] }],
        tags: {},
      },
    ],
    users: async () => [{ userName: "alice", arn: USER, identityStatements: [], tags: {} }],
    credentialReport: async () => [
      { user: "<root_account>", arn: `arn:aws:iam::${ACCOUNT}:root`, passwordEnabled: true, mfaActive: false, accessKey1Active: true, accessKey2Active: false },
      { user: "alice", arn: USER, passwordEnabled: true, mfaActive: false, accessKey1Active: true, accessKey1LastRotated: "2025-01-01T00:00:00Z", accessKey1LastUsed: "2025-02-01T00:00:00Z", accessKey2Active: false },
    ],
    accountSummary: async () => ({
      rootMfaEnabled: false,
      rootAccessKeysPresent: true,
      passwordPolicy: null,
      s3PublicAccessBlock: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: false, restrictPublicBuckets: false },
    }),
    cloudTrails: async () => [
      { name: "main", arn: `arn:aws:cloudtrail:${REGION}:${ACCOUNT}:trail/main`, homeRegion: REGION, isMultiRegion: false, isLogging: true, logFileValidationEnabled: false, managementEvents: true },
    ],
    regionSettings: async () => ({ ebsEncryptionByDefault: false, configRecorderEnabled: false, guardDutyEnabled: true }),
    s3Buckets: async () => [
      {
        name: "data-bucket",
        arn: BUCKET,
        region: REGION,
        publicAccessBlock: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true },
        policyIsPublic: false,
        policyStatements: projectPolicyDocument({
          Statement: [
            { Effect: "Allow", Principal: { AWS: `arn:aws:iam::${ACCOUNT}:root` }, Action: "s3:GetObject", Resource: `${BUCKET}/*` },
            { Effect: "Deny", Principal: "*", Action: "s3:*", Resource: [BUCKET, `${BUCKET}/*`], Condition: { Bool: { "aws:SecureTransport": "false" } } },
          ],
        }),
        encryption: "aws:kms",
        versioning: true,
        loggingEnabled: false,
        tags: {},
      },
    ],
    ebsVolumes: async () => [{ volumeId: "vol-1", encrypted: false, attachedInstanceIds: ["i-1"], sizeGiB: 8, tags: {} }],
    ebsSnapshots: async () => [{ snapshotId: "snap-1", volumeId: "vol-1", encrypted: false, public: true, tags: {} }],
    kmsKeys: async () => [
      {
        keyId: "1111-2222",
        arn: KEY,
        manager: "CUSTOMER",
        enabled: true,
        rotationEnabled: false,
        aliases: ["alias/data"],
        policyStatements: projectPolicyDocument({
          Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${ACCOUNT}:root` }, Action: "kms:*", Resource: "*" }],
        }),
        tags: {},
      },
    ],
  };
}

test("phase 3 collectors produce the new node types with the attributes rules need", async () => {
  const g = await discoverGraph(richClient());
  parseGraph(g);
  assert.deepEqual(checkReferentialIntegrity(g), []);
  const byType = (t: string) => g.nodes.filter((n) => n.type === t);

  assert.equal(byType("aws::s3::bucket").length, 1);
  assert.equal(byType("aws::s3::bucket")[0]!.attributes["encryption"], "aws:kms");
  assert.equal(byType("aws::ec2::volume")[0]!.attributes["encrypted"], false);
  assert.equal(byType("aws::ec2::snapshot")[0]!.attributes["public"], true);
  assert.equal(byType("aws::kms::key")[0]!.attributes["rotationEnabled"], false);
  assert.equal(byType("aws::kms::key")[0]!.name, "alias/data");
  assert.equal(byType("aws::cloudtrail::trail")[0]!.attributes["isMultiRegion"], false);
  assert.equal(byType("aws::ec2::vpc")[0]!.attributes["flowLogsEnabled"], false);
  assert.equal(byType("aws::rds::db-instance")[0]!.attributes["storageEncrypted"], false);
  assert.deepEqual(byType("aws::lambda::function")[0]!.attributes["urlAuthTypes"], ["NONE"]);

  const account = byType("aws::account")[0]!;
  assert.equal(account.attributes["rootMfaEnabled"], false);
  assert.equal(account.attributes["rootAccessKeysPresent"], true);
  assert.equal(account.attributes["cloudTrailMultiRegionLogging"], false);
  assert.equal((account.attributes["s3PublicAccessBlock"] as { blockPublicPolicy: boolean }).blockPublicPolicy, false);
  const region = byType("aws::region")[0]!;
  assert.equal(region.attributes["ebsEncryptionByDefault"], false);
  assert.equal(region.attributes["guardDutyEnabled"], true);
  const alice = byType("aws::iam::user")[0]!;
  assert.equal(alice.attributes["mfaActive"], false);
  assert.equal(alice.attributes["accessKey1LastRotated"], "2025-01-01T00:00:00Z");

  // Volume attaches to its instance; both live in the instance's subnet.
  const vol = byType("aws::ec2::volume")[0]!;
  const inst = byType("aws::ec2::instance")[0]!;
  assert.equal(vol.parent, inst.parent);
  assert.ok(g.edges.some((e) => e.relationship === "attached-to" && e.source === vol.id && e.target === inst.id));

  // Capabilities are declared on the graph.
  for (const c of ["s3:bucket", "kms:key", "ec2:volume", "ec2:snapshot", "cloudtrail:trail", "iam:credential-report", "iam:account-summary", "account:region-settings", "lambda:policy", "iam:user"]) {
    assert.ok(g.meta.capabilities?.includes(c), c);
  }
});

test("resource-policy pass: public lambda, external secret access, same-account bucket via identity", async () => {
  const g = await discoverGraph(richClient());
  const access = g.edges.filter((e) => e.relationship === "can-access");
  const fn = g.nodes.find((n) => n.type === "aws::lambda::function")!;
  const secret = g.nodes.find((n) => n.type === "aws::secretsmanager::secret")!;

  const pub = g.findings.find((f) => f.kind === "public-resource");
  assert.ok(pub, "public lambda URL policy → public-resource");
  assert.equal(pub!.nodeId, fn.id);
  assert.equal(pub!.severity, "critical");
  assert.ok(access.some((e) => e.target === fn.id && e.attributes["public"] === true));

  const ext = g.findings.find((f) => f.kind === "external-can-access");
  assert.ok(ext, "partner role on the secret → external-can-access");
  assert.equal(ext!.nodeId, secret.id);
  assert.equal(ext!.severity, "high");
  assert.ok(g.nodes.some((n) => n.type === "aws::iam::external-principal" && n.account === "999988887777"));

  // Bucket policy trusts the account root → the Reader role's identity policy grants GetObject → edge; alice has none → no edge.
  const bucketEdges = access.filter((e) => e.target === BUCKET);
  assert.deepEqual(bucketEdges.map((e) => e.source), [ROLE]);
  assert.equal(bucketEdges[0]!.attributes["via"], "identity+resource");
  // KMS key policy trusts root with kms:* → same logic; Reader has no kms allow → no edge, and no finding.
  assert.ok(!access.some((e) => e.target === KEY));
  assert.ok(!g.findings.some((f) => f.nodeId === BUCKET), "same-account bucket policy is not an exposure");
  assert.deepEqual(checkReferentialIntegrity(g), []);
});

test("regional + global merge keeps one external-principal node and all capabilities", async () => {
  const global = await discoverGraph(richClient(), { scope: "global" });
  const regional = await discoverGraph(richClient(), { scope: "regional" });
  assert.ok(!regional.nodes.some((n) => n.type === "aws::cloudtrail::trail"));
  assert.ok(regional.nodes.some((n) => n.type === "aws::s3::bucket"));
  assert.ok(global.nodes.some((n) => n.type === "aws::cloudtrail::trail"));
  assert.ok(!global.meta.capabilities?.includes("s3:bucket"));
  assert.ok(regional.meta.capabilities?.includes("s3:bucket"));
  // Regional pass has no principals, so the bucket's root grant yields no edge; public/external still do.
  assert.ok(regional.findings.some((f) => f.kind === "public-resource"));
  const merged = mergeGraphs([global, regional], { generatedAt: "2026-09-19T00:00:00Z", source: "aws-live" });
  assert.deepEqual(checkReferentialIntegrity(merged), []);
  assert.ok(merged.meta.capabilities?.includes("s3:bucket") && merged.meta.capabilities?.includes("cloudtrail:trail"));
  const ext = merged.nodes.filter((n) => n.type === "aws::iam::external-principal");
  assert.equal(new Set(ext.map((n) => n.id)).size, ext.length);
});

test("redaction keeps posture booleans and drops policy statements and the password policy", async () => {
  const red = redactGraph(await discoverGraph(richClient()));
  const bucket = red.nodes.find((n) => n.type === "aws::s3::bucket")!;
  assert.equal(bucket.attributes["policyStatements"], undefined);
  assert.equal(bucket.attributes["versioning"], true);
  assert.equal(bucket.attributes["encryption"], undefined, "free-form string dropped unless allowlisted");
  const account = red.nodes.find((n) => n.type === "aws::account")!;
  assert.equal(account.attributes["rootMfaEnabled"], false);
  assert.equal(account.attributes["passwordPolicy"], undefined);
});

test("analyzeResourceAccess unit: conditions lower severity, NotPrincipal is public, specific same-account ARN gets a direct edge", () => {
  const principals: AnalyzedPrincipal[] = [
    { id: USER, account: ACCOUNT, kind: "user", identity: [] },
  ];
  const r = analyzeResourceAccess(
    principals,
    [
      {
        id: BUCKET, type: "aws::s3::bucket", account: ACCOUNT, actions: ["s3:GetObject"], resourceAliases: [`${BUCKET}/*`],
        statements: projectPolicyDocument({
          Statement: [
            { Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: `${BUCKET}/*`, Condition: { StringEquals: { "aws:PrincipalOrgID": "o-123" } } },
            { Effect: "Allow", Principal: { AWS: USER }, Action: "s3:GetObject", Resource: `${BUCKET}/*` },
            { Effect: "Allow", NotPrincipal: { AWS: USER }, Action: "s3:ListBucket", Resource: BUCKET },
          ],
        }),
      },
      {
        id: KEY, type: "aws::kms::key", account: ACCOUNT, actions: ["kms:Decrypt"],
        statements: projectPolicyDocument({
          Statement: [{ Effect: "Allow", Principal: { AWS: "999988887777" }, Action: "kms:Decrypt", Resource: "*", Condition: { StringEquals: { "kms:ViaService": "s3.us-east-1.amazonaws.com" } } }],
        }),
      },
    ],
    ACCOUNT,
    "acct",
  );
  const pub = r.findings.filter((f) => f.kind === "public-resource");
  assert.equal(pub.length, 1, "one public finding per resource");
  // The first matching public statement is conditioned → high; NotPrincipal would be critical but dedupes to the first.
  assert.equal(pub[0]!.severity, "high");
  assert.ok(pub[0]!.detail.includes("aws:PrincipalOrgID"));
  const ext = r.findings.find((f) => f.kind === "external-can-access")!;
  assert.equal(ext.severity, "medium", "conditioned external grant is medium");
  assert.ok(r.edges.some((e) => e.source === USER && e.target === BUCKET && e.attributes["via"] === "resource"));
  assert.ok(r.edges.some((e) => e.source === "aws::iam::external-principal::999988887777" && e.target === KEY));
});

test("projectPolicyDocument handles strings, url-encoded strings, objects, and garbage", () => {
  const obj = { Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: ["sts:AssumeRole"] }] };
  const a = projectPolicyDocument(obj);
  const b = projectPolicyDocument(JSON.stringify(obj));
  const c = projectPolicyDocument(encodeURIComponent(JSON.stringify(obj)));
  assert.deepEqual(a, b);
  assert.deepEqual(a, c);
  assert.deepEqual(a[0]!.principals, [{ type: "service", value: "lambda.amazonaws.com" }]);
  assert.deepEqual(projectPolicyDocument("not json"), []);
  assert.deepEqual(projectPolicyDocument(undefined), []);
  assert.deepEqual(projectPolicyDocument({ Statement: { Effect: "Allow", Principal: "*", Action: "*" } })[0]!.principals, [{ type: "*", value: "*" }]);
});
