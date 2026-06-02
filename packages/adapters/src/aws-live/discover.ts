import type { CloudNode, CloudEdge, Finding, Graph } from "@kumomiru/graph";
import { Containers } from "../common/containers.js";
import {
  scanText,
  scanRecord,
  marker,
  plaintextSecretFinding,
} from "../common/sanitize.js";
import {
  analyzeAssumeRole,
  type AnalyzedPrincipal,
} from "../analysis/iam.js";
import {
  analyzeDataflow,
  type DataflowIngress,
  type DataflowMember,
  type DataflowReference,
} from "../analysis/dataflow.js";
import type { DiscoveryClient } from "./client.js";

const SOURCE = "aws-live";

/** ARN helpers for stable node ids. */
const vpcArn = (acct: string, region: string, id: string) =>
  `arn:aws:ec2:${region}:${acct}:vpc/${id}`;
const subnetArn = (acct: string, region: string, id: string) =>
  `arn:aws:ec2:${region}:${acct}:subnet/${id}`;
const igwArn = (acct: string, region: string, id: string) =>
  `arn:aws:ec2:${region}:${acct}:internet-gateway/${id}`;
const sgArn = (acct: string, region: string, id: string) =>
  `arn:aws:ec2:${region}:${acct}:security-group/${id}`;
const instArn = (acct: string, region: string, id: string) =>
  `arn:aws:ec2:${region}:${acct}:instance/${id}`;
const dbArn = (acct: string, region: string, id: string) =>
  `arn:aws:rds:${region}:${acct}:db:${id}`;
const fnArn = (acct: string, region: string, id: string) =>
  `arn:aws:lambda:${region}:${acct}:function:${id}`;

function nameFromTags(tags: Record<string, string>, fallback: string): string {
  return tags["Name"] ?? fallback;
}

/** True when an ingress rule is open to the internet. */
function isInternetFacing(cidrs: string[]): boolean {
  return cidrs.includes("0.0.0.0/0") || cidrs.includes("::/0");
}

/**
 * The core discovery pass: read everything from the (read-only) client and
 * normalize into a Graph. Pure with respect to the client — no SDK, no creds
 * here — so it is fully unit-testable with a fake client.
 *
 * Edges produced (network + iam):
 *   - IGW attached-to VPC
 *   - SG protects instance; internet-facing ingress -> instance (allows-ingress)
 *   - can-assume edges from the shared IAM analysis pass (trust ∩ identity for
 *     internal principals; trust-only exposure for external ones)
 *
 * IAM is intentionally NOT computed inline here: node collection assembles the
 * principal set, then `analyzeAssumeRole` (the shared brain, used by every
 * adapter) emits the lens:'iam' edges and external-can-assume findings.
 *
 * Secrets discovered in user-data / env vars are detected, redacted to markers,
 * and raised as findings. Secrets Manager secrets are listed as nodes; values
 * are never fetched.
 */
export async function discoverGraph(client: DiscoveryClient): Promise<Graph> {
  const account = await client.accountId();
  const region = client.region();
  const containers = new Containers();
  const regionId = containers.region(account, region);

  const nodes: CloudNode[] = [];
  const edges: CloudEdge[] = [];
  const findings: Finding[] = [];

  // Index raw AWS ids -> node ids for edge wiring.
  const vpcNode = new Map<string, string>();
  const subnetNode = new Map<string, string>();
  const sgNode = new Map<string, string>();
  const instNode = new Map<string, string>();

  // Inputs accumulated for the dataflow analysis pass (run after collection).
  const dfMembers: DataflowMember[] = [];
  const dfIngress: DataflowIngress[] = [];
  const dfLambdas: Array<{ id: string; env: Record<string, string> }> = [];

  // --- VPCs ----------------------------------------------------------------
  for (const vpc of await client.vpcs()) {
    const id = vpcArn(account, region, vpc.vpcId);
    vpcNode.set(vpc.vpcId, id);
    nodes.push({
      id,
      type: "aws::ec2::vpc",
      name: nameFromTags(vpc.tags, vpc.vpcId),
      account,
      region,
      parent: regionId,
      tags: vpc.tags,
      attributes: vpc.cidrBlock ? { cidrBlock: vpc.cidrBlock } : {},
    });
  }

  // --- Subnets -------------------------------------------------------------
  for (const subnet of await client.subnets()) {
    const id = subnetArn(account, region, subnet.subnetId);
    subnetNode.set(subnet.subnetId, id);
    nodes.push({
      id,
      type: "aws::ec2::subnet",
      name: nameFromTags(subnet.tags, subnet.subnetId),
      account,
      region,
      parent: vpcNode.get(subnet.vpcId) ?? regionId,
      tags: subnet.tags,
      attributes: {
        ...(subnet.cidrBlock ? { cidrBlock: subnet.cidrBlock } : {}),
        ...(subnet.availabilityZone
          ? { availabilityZone: subnet.availabilityZone }
          : {}),
        mapPublicIpOnLaunch: subnet.mapPublicIpOnLaunch ?? false,
      },
    });
  }

  // --- Internet gateways ---------------------------------------------------
  for (const igw of await client.internetGateways()) {
    const id = igwArn(account, region, igw.internetGatewayId);
    const parent = igw.attachedVpcId
      ? (vpcNode.get(igw.attachedVpcId) ?? regionId)
      : regionId;
    nodes.push({
      id,
      type: "aws::ec2::internet-gateway",
      name: nameFromTags(igw.tags, igw.internetGatewayId),
      account,
      region,
      parent,
      tags: igw.tags,
      attributes: {},
    });
    if (igw.attachedVpcId && vpcNode.has(igw.attachedVpcId)) {
      edges.push({
        id: `e-igw-${igw.internetGatewayId}`,
        source: id,
        target: vpcNode.get(igw.attachedVpcId)!,
        relationship: "attached-to",
        lens: "network",
        attributes: {},
      });
    }
  }

  // --- Security groups -----------------------------------------------------
  const sgInternetIngress = new Map<string, { ports: string }>();
  for (const sg of await client.securityGroups()) {
    const id = sgArn(account, region, sg.groupId);
    sgNode.set(sg.groupId, id);
    nodes.push({
      id,
      type: "aws::ec2::security-group",
      name: sg.groupName ?? sg.groupId,
      account,
      region,
      parent: sg.vpcId ? (vpcNode.get(sg.vpcId) ?? regionId) : regionId,
      tags: sg.tags,
      attributes: {},
    });
    // Record whether this SG exposes anything to the internet, and capture
    // SG-to-SG rules for the dataflow pass (who may reach this group, on what).
    for (const rule of sg.ingress) {
      const ports = portLabel(rule.fromPort, rule.toPort);
      if (isInternetFacing(rule.cidrs)) {
        sgInternetIngress.set(sg.groupId, { ports });
      }
      if (rule.sourceGroupIds && rule.sourceGroupIds.length > 0) {
        dfIngress.push({
          groupId: sg.groupId,
          sourceGroupIds: rule.sourceGroupIds,
          ports,
        });
      }
    }
  }

  // --- Instances -----------------------------------------------------------
  for (const inst of await client.instances()) {
    const id = instArn(account, region, inst.instanceId);
    instNode.set(inst.instanceId, id);
    const attributes: Record<string, unknown> = {
      ...(inst.instanceType ? { instanceType: inst.instanceType } : {}),
      ...(inst.publicIp ? { publicIp: inst.publicIp } : {}),
      ...(inst.privateIp ? { privateIp: inst.privateIp } : {}),
    };

    // Scan user-data for hard-coded secrets; redact to a marker + finding.
    if (inst.userData) {
      const res = scanText(inst.userData);
      if (res.found) {
        attributes["userDataSecret"] = marker(res.kinds[0] ?? "secret");
        findings.push(
          plaintextSecretFinding(id, "EC2 user-data", res.kinds),
        );
      }
    }

    nodes.push({
      id,
      type: "aws::ec2::instance",
      name: nameFromTags(inst.tags, inst.instanceId),
      account,
      region,
      parent: inst.subnetId
        ? (subnetNode.get(inst.subnetId) ?? regionId)
        : regionId,
      tags: inst.tags,
      attributes,
    });
    // Remember SG membership so the dataflow pass can expand SG-to-SG rules.
    dfMembers.push({ id, groupIds: inst.securityGroupIds });

    // SG membership + internet-facing ingress edges.
    for (const sgId of inst.securityGroupIds) {
      const sgId2 = sgNode.get(sgId);
      if (sgId2) {
        edges.push({
          id: `e-sgm-${sgId}-${inst.instanceId}`,
          source: sgId2,
          target: id,
          relationship: "protects",
          lens: "network",
          attributes: {},
        });
      }
      const exposed = sgInternetIngress.get(sgId);
      if (exposed) {
        edges.push({
          id: `e-net-${sgId}-${inst.instanceId}`,
          source: sgId2 ?? id,
          target: id,
          relationship: "allows-ingress",
          lens: "network",
          attributes: {
            ports: exposed.ports,
            from: "0.0.0.0/0",
            internetFacing: true,
          },
        });
      }
    }
  }

  // --- RDS -----------------------------------------------------------------
  for (const db of await client.dbInstances()) {
    const id = dbArn(account, region, db.dbInstanceIdentifier);
    const parentSubnet = db.subnetIds
      .map((s) => subnetNode.get(s))
      .find((n): n is string => Boolean(n));
    nodes.push({
      id,
      type: "aws::rds::db-instance",
      name: db.dbInstanceIdentifier,
      account,
      region,
      parent: parentSubnet ?? regionId,
      tags: db.tags,
      attributes: {
        ...(db.engine ? { engine: db.engine } : {}),
        ...(db.port ? { port: db.port } : {}),
        publiclyAccessible: db.publiclyAccessible ?? false,
      },
    });
  }

  // --- Lambda --------------------------------------------------------------
  for (const fn of await client.functions()) {
    const id = fnArn(account, region, fn.functionName);
    const attributes: Record<string, unknown> = {
      ...(fn.runtime ? { runtime: fn.runtime } : {}),
    };
    // Scan env vars for secrets.
    const res = scanRecord(fn.environment);
    if (res.found) {
      attributes["environmentSecret"] = marker(res.kinds[0] ?? "secret");
      findings.push(
        plaintextSecretFinding(id, "Lambda environment variables", res.kinds),
      );
    }
    nodes.push({
      id,
      type: "aws::lambda::function",
      name: fn.functionName,
      account,
      region,
      parent: regionId,
      tags: fn.tags,
      attributes,
    });
    // Keep the env for the dataflow pass: values that name another resource are
    // explicit references. The value itself is never stored on the graph.
    dfLambdas.push({ id, env: fn.environment });
  }

  // --- Secrets Manager (listed, never resolved) ----------------------------
  for (const secret of await client.secrets()) {
    nodes.push({
      id: secret.arn,
      type: "aws::secretsmanager::secret",
      name: secret.name,
      account,
      region,
      parent: regionId,
      tags: secret.tags,
      attributes: { secretPresent: true, valueResolved: false },
    });
  }

  // --- IAM principals ------------------------------------------------------
  // Collect roles and users as principal nodes, then hand the assembled set to
  // the shared assume-role analysis pass (the brain). No edges are computed
  // inline: that is what keeps IAM correct in one place across every adapter.
  const accountNode = containers.account(account);
  const principals: AnalyzedPrincipal[] = [];

  for (const role of await client.roles()) {
    const serviceTrust = role.trustedPrincipals.find(
      (p) => p.type === "service",
    );
    nodes.push({
      id: role.arn,
      type: "aws::iam::role",
      name: role.roleName,
      account,
      parent: accountNode,
      tags: role.tags,
      attributes: serviceTrust ? { trustedService: serviceTrust.value } : {},
    });
    principals.push({
      id: role.arn,
      account,
      kind: "role",
      identity: role.identityStatements ?? [],
      trust: role.trustedPrincipals.map((p) => ({
        principalValue: p.value,
        type: p.type,
        conditionKeys: p.conditionKeys ?? [],
      })),
    });
  }

  for (const user of (await client.users?.()) ?? []) {
    nodes.push({
      id: user.arn,
      type: "aws::iam::user",
      name: user.userName,
      account,
      parent: accountNode,
      tags: user.tags,
      attributes: {},
    });
    principals.push({
      id: user.arn,
      account,
      kind: "user",
      identity: user.identityStatements ?? [],
    });
  }

  // --- IAM analysis pass (assume-role graph: trust ∩ identity) -------------
  const iam = analyzeAssumeRole(principals, account, accountNode);
  nodes.push(...iam.nodes);
  edges.push(...iam.edges);
  findings.push(...iam.findings);

  // --- Dataflow analysis pass (SG reachability + explicit refs) ------------
  // Resolve Lambda env values that name an existing resource into references.
  // The matched value is never stored — only the resulting edge.
  const refTargets = nodes.filter((n) => !CONTAINER_TYPES.has(n.type));
  const references: DataflowReference[] = [];
  for (const lambda of dfLambdas) {
    const seen = new Set<string>();
    for (const value of Object.values(lambda.env)) {
      if (typeof value !== "string" || value.length < 4) continue;
      for (const target of refTargets) {
        if (target.id === lambda.id || seen.has(target.id)) continue;
        const byArn = value.includes(target.id);
        const byName =
          target.type === "aws::rds::db-instance" &&
          target.name.length >= 4 &&
          value.includes(target.name);
        if (byArn || byName) {
          seen.add(target.id);
          references.push({
            from: lambda.id,
            to: target.id,
            relationship: dataflowRelationship(target.type),
            via: "lambda-env",
          });
        }
      }
    }
  }
  const dataflow = analyzeDataflow({
    members: dfMembers,
    ingress: dfIngress,
    references,
  });
  edges.push(...dataflow.edges);

  return {
    nodes: [...containers.nodes.values(), ...nodes],
    edges,
    findings,
    meta: { generatedAt: new Date(0).toISOString(), source: SOURCE, provider: "aws" },
  };
}

/** Container node types — never dataflow reference targets. */
const CONTAINER_TYPES = new Set<string>([
  "aws::account",
  "aws::region",
  "aws::ec2::vpc",
  "aws::ec2::subnet",
]);

/** Human-readable port (or range) for an SG rule's from/to ports. */
function portLabel(fromPort?: number, toPort?: number): string {
  if (fromPort === toPort) return String(fromPort ?? "all");
  return `${fromPort ?? 0}-${toPort ?? 65535}`;
}

/** Dataflow edge relationship for a referenced resource type. */
function dataflowRelationship(type: string): string {
  switch (type) {
    case "aws::secretsmanager::secret":
    case "aws::dynamodb::table":
      return "reads-from";
    case "aws::rds::db-instance":
      return "connects-to";
    default:
      return "references";
  }
}
