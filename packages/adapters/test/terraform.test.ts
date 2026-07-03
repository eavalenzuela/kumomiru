import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { parseGraph, checkReferentialIntegrity } from "@kumomiru/graph";
import { terraformAdapter } from "../src/index.js";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/simple.tfstate.json", import.meta.url)),
    "utf8",
  ),
);

test("produces a schema-valid, referentially-intact graph", () => {
  const graph = terraformAdapter.toGraph(fixture);
  parseGraph(graph); // throws on schema mismatch
  assert.deepEqual(checkReferentialIntegrity(graph), []);
  assert.equal(graph.meta.source, "terraform-state");
});

test("maps managed resources, skips data sources", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const types = graph.nodes.map((n) => n.type);
  assert.ok(types.includes("aws::ec2::vpc"));
  assert.ok(types.includes("aws::ec2::instance"));
  assert.ok(types.includes("aws::iam::role"));
  // the aws_caller_identity data source must not appear
  assert.ok(!graph.nodes.some((n) => n.name === "current"));
});

test("synthesizes account and region container nodes", () => {
  const graph = terraformAdapter.toGraph(fixture);
  assert.ok(graph.nodes.some((n) => n.type === "aws::account"));
  assert.ok(graph.nodes.some((n) => n.type === "aws::region"));
});

test("builds the containment chain account -> region -> vpc -> subnet -> instance", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const inst = graph.nodes.find((n) => n.type === "aws::ec2::instance")!;
  const subnet = byId.get(inst.parent!)!;
  assert.equal(subnet.type, "aws::ec2::subnet");
  const vpc = byId.get(subnet.parent!)!;
  assert.equal(vpc.type, "aws::ec2::vpc");
  const region = byId.get(vpc.parent!)!;
  assert.equal(region.type, "aws::region");
  const account = byId.get(region.parent!)!;
  assert.equal(account.type, "aws::account");
});

test("IAM role is parented to the account, not a region", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const role = graph.nodes.find((n) => n.type === "aws::iam::role")!;
  assert.equal(byId.get(role.parent!)!.type, "aws::account");
});

test("derives network edges: IGW attachment and SG membership", () => {
  const graph = terraformAdapter.toGraph(fixture);
  const rels = graph.edges.map((e) => e.relationship);
  assert.ok(rels.includes("attached-to"));
  assert.ok(rels.includes("protects"));
  assert.ok(graph.edges.every((e) => e.lens === "network"));
});

test("detects plaintext secrets in user-data and tags, never storing the value", () => {
  const state = {
    version: 4,
    resources: [
      {
        mode: "managed",
        type: "aws_instance",
        name: "web",
        instances: [
          {
            attributes: {
              arn: "arn:aws:ec2:us-east-1:123456789012:instance/i-secret01",
              id: "i-secret01",
              instance_type: "t3.small",
              user_data: "#!/bin/bash\nexport AWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
              tags: { Name: "web", DB_PASSWORD: "hunter2supersecret" },
            },
          },
        ],
      },
    ],
  };
  const graph = terraformAdapter.toGraph(state);
  const json = JSON.stringify(graph);
  // The actual secret values must never appear anywhere in the graph.
  assert.ok(!json.includes("AKIAIOSFODNN7EXAMPLE"), "AWS key leaked");
  assert.ok(!json.includes("hunter2supersecret"), "tag secret leaked");
  // Two findings: one for user-data, one for the tag.
  const kinds = graph.findings.map((f) => f.kind);
  assert.equal(kinds.filter((k) => k === "plaintext-secret").length, 2);
  const inst = graph.nodes.find((n) => n.type === "aws::ec2::instance")!;
  assert.equal(
    (inst.attributes["userDataSecret"] as { secretPresent?: boolean })
      .secretPresent,
    true,
  );
  assert.equal(inst.tags["DB_PASSWORD"], "[redacted-secret]");
});

test("IAM lens: external trust in assume_role_policy raises a critical finding", () => {
  const state = {
    version: 4,
    resources: [
      {
        mode: "managed",
        type: "aws_iam_role",
        name: "admin",
        instances: [
          {
            attributes: {
              arn: "arn:aws:iam::123456789012:role/OrgAdmin",
              id: "OrgAdmin",
              name: "OrgAdmin",
              assume_role_policy: JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                  {
                    Effect: "Allow",
                    Principal: { AWS: "arn:aws:iam::999988887777:root" },
                    Action: "sts:AssumeRole",
                  },
                ],
              }),
            },
          },
        ],
      },
    ],
  };
  const graph = terraformAdapter.toGraph(state);
  // Structurally intact even with the synthesized external-principal node.
  assert.deepEqual(checkReferentialIntegrity(graph), []);
  const f = graph.findings.find((f) => f.kind === "external-can-assume");
  assert.ok(f, "expected an external-can-assume finding");
  assert.equal(f!.severity, "critical");
  const edge = graph.edges.find(
    (e) => e.lens === "iam" && e.attributes["external"] === true,
  );
  assert.ok(edge, "expected an external can-assume iam edge");
});

test("IAM lens: internal can-assume needs BOTH trust and identity", () => {
  const targetArn = "arn:aws:iam::123456789012:role/deploy";
  const userArn = "arn:aws:iam::123456789012:user/ci";
  const state = {
    version: 4,
    resources: [
      {
        mode: "managed",
        type: "aws_iam_role",
        name: "deploy",
        instances: [
          {
            attributes: {
              arn: targetArn,
              id: "deploy",
              name: "deploy",
              assume_role_policy: JSON.stringify({
                Statement: [
                  {
                    Effect: "Allow",
                    Principal: { AWS: userArn },
                    Action: "sts:AssumeRole",
                  },
                ],
              }),
            },
          },
        ],
      },
      {
        mode: "managed",
        type: "aws_iam_user",
        name: "ci",
        instances: [{ attributes: { arn: userArn, id: "ci", name: "ci" } }],
      },
      {
        mode: "managed",
        type: "aws_iam_user_policy",
        name: "ci-assume",
        instances: [
          {
            attributes: {
              user: "ci",
              policy: JSON.stringify({
                Statement: [
                  {
                    Effect: "Allow",
                    Action: "sts:AssumeRole",
                    Resource: targetArn,
                  },
                ],
              }),
            },
          },
        ],
      },
    ],
  };
  const graph = terraformAdapter.toGraph(state);
  assert.ok(graph.nodes.some((n) => n.type === "aws::iam::user"));
  const edge = graph.edges.find(
    (e) => e.lens === "iam" && e.source === userArn && e.target === targetArn,
  );
  assert.ok(edge, "expected an internal can-assume edge");
  assert.equal(edge!.attributes["identityConfirmed"], true);
});

test("dataflow lens: an SG-to-SG ingress rule becomes a talks-to edge", () => {
  const webArn = "arn:aws:ec2:us-east-1:123456789012:instance/i-web";
  const dbArn = "arn:aws:ec2:us-east-1:123456789012:instance/i-db";
  const state = {
    version: 4,
    resources: [
      {
        mode: "managed",
        type: "aws_security_group",
        name: "web",
        instances: [
          {
            attributes: {
              arn: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-web",
              id: "sg-web",
              name: "web-sg",
            },
          },
        ],
      },
      {
        mode: "managed",
        type: "aws_security_group",
        name: "db",
        instances: [
          {
            attributes: {
              arn: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-db",
              id: "sg-db",
              name: "db-sg",
              ingress: [
                {
                  from_port: 5432,
                  to_port: 5432,
                  protocol: "tcp",
                  security_groups: ["sg-web"],
                },
              ],
            },
          },
        ],
      },
      {
        mode: "managed",
        type: "aws_instance",
        name: "web",
        instances: [
          {
            attributes: {
              arn: webArn,
              id: "i-web",
              vpc_security_group_ids: ["sg-web"],
              tags: { Name: "web" },
            },
          },
        ],
      },
      {
        mode: "managed",
        type: "aws_instance",
        name: "db",
        instances: [
          {
            attributes: {
              arn: dbArn,
              id: "i-db",
              vpc_security_group_ids: ["sg-db"],
              tags: { Name: "db" },
            },
          },
        ],
      },
    ],
  };
  const graph = terraformAdapter.toGraph(state);
  const flow = graph.edges.find(
    (e) =>
      e.lens === "dataflow" &&
      e.relationship === "talks-to" &&
      e.attributes["ports"] === "5432",
  );
  assert.ok(flow, "expected an SG-derived dataflow edge");
  assert.equal(flow!.source, webArn);
  assert.equal(flow!.target, dbArn);
});

test("network lens: a 0.0.0.0/0 ingress rule flags internet exposure", () => {
  const webArn = "arn:aws:ec2:us-east-1:123456789012:instance/i-web";
  const state = {
    version: 4,
    resources: [
      {
        mode: "managed",
        type: "aws_security_group",
        name: "web",
        instances: [
          {
            attributes: {
              arn: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-web",
              id: "sg-web",
              name: "web-sg",
              ingress: [
                {
                  from_port: 443,
                  to_port: 443,
                  protocol: "tcp",
                  cidr_blocks: ["0.0.0.0/0"],
                },
              ],
            },
          },
        ],
      },
      {
        mode: "managed",
        type: "aws_instance",
        name: "web",
        instances: [
          {
            attributes: {
              arn: webArn,
              id: "i-web",
              vpc_security_group_ids: ["sg-web"],
              tags: { Name: "web" },
            },
          },
        ],
      },
    ],
  };
  const graph = terraformAdapter.toGraph(state);
  const exposed = graph.edges.find(
    (e) => e.attributes["internetFacing"] === true,
  );
  assert.ok(exposed, "expected an internet-facing edge");
  assert.equal(exposed!.lens, "network");
  assert.equal(exposed!.target, webArn);
  assert.notEqual(exposed!.source, exposed!.target); // never a self-loop
});
