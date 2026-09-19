import {
  isContainer,
  type CloudNode,
  type CloudEdge,
  type Finding,
  type Graph,
} from "@kumomiru/graph";
import { Containers } from "../common/containers.js";
import { ingressAttribute } from "../common/ingress.js";
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

/**
 * What a full live discovery collects — the rule engine's `requires`
 * vocabulary. A rule whose requirement is absent reports `not-assessed`
 * instead of silently passing. Both adapters produce this set today.
 */
export const DISCOVERY_CAPABILITIES = [
  "ec2:vpc",
  "ec2:subnet",
  "ec2:internet-gateway",
  "ec2:security-group",
  "ec2:instance",
  "rds:db-instance",
  "lambda:function",
  "secretsmanager:secret",
  "iam:role",
  "iam:user",
] as const;

/**
 * ARN helpers for stable node ids, bound to the account's partition so ids
 * match the real ARNs IAM returns (`arn:aws-us-gov:...` in GovCloud, etc.).
 */
function arnHelpers(partition: string) {
  const p = partition;
  return {
    vpc: (acct: string, region: string, id: string) =>
      `arn:${p}:ec2:${region}:${acct}:vpc/${id}`,
    subnet: (acct: string, region: string, id: string) =>
      `arn:${p}:ec2:${region}:${acct}:subnet/${id}`,
    igw: (acct: string, region: string, id: string) =>
      `arn:${p}:ec2:${region}:${acct}:internet-gateway/${id}`,
    sg: (acct: string, region: string, id: string) =>
      `arn:${p}:ec2:${region}:${acct}:security-group/${id}`,
    inst: (acct: string, region: string, id: string) =>
      `arn:${p}:ec2:${region}:${acct}:instance/${id}`,
    db: (acct: string, region: string, id: string) =>
      `arn:${p}:rds:${region}:${acct}:db:${id}`,
    fn: (acct: string, region: string, id: string) =>
      `arn:${p}:lambda:${region}:${acct}:function:${id}`,
  };
}

/**
 * Which slice of the account a single `discoverGraph` call collects.
 *
 * - `all` (default): everything, one region — the ad-hoc `/map/live` path.
 * - `regional`: region-scoped resources only (VPCs, instances, RDS, Lambda,
 *   secrets, network + dataflow edges). No IAM principals, no IAM pass.
 * - `global`: IAM roles/users and the assume-role analysis only. IAM is not
 *   regional, so the scheduled scanner runs this once per account and then
 *   `mergeGraphs` it with one `regional` graph per region.
 */
export type DiscoverScope = "all" | "regional" | "global";

export interface DiscoverOptions {
  /** Clock for `meta.generatedAt`; injectable for deterministic tests. */
  now?: () => Date;
  scope?: DiscoverScope;
}

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
export async function discoverGraph(
  client: DiscoveryClient,
  opts: DiscoverOptions = {},
): Promise<Graph> {
  const account = await client.accountId();
  const partition = (await client.partition?.()) ?? "aws";
  const region = client.region();
  const scope: DiscoverScope = opts.scope ?? "all";
  const doRegional = scope !== "global";
  const doGlobal = scope !== "regional";
  const arn = arnHelpers(partition);
  const containers = new Containers();
  // A global-only pass must not synthesize a region container it never fills.
  const regionId = doRegional
    ? containers.region(account, region)
    : containers.account(account);

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

  if (doRegional) {
    // --- VPCs ----------------------------------------------------------------
    for (const vpc of await client.vpcs()) {
      const id = arn.vpc(account, region, vpc.vpcId);
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
    const id = arn.subnet(account, region, subnet.subnetId);
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
    const id = arn.igw(account, region, igw.internetGatewayId);
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
  const sgInternetIngress = new Map<string, { ports: string; cidr: string }>();
  for (const sg of await client.securityGroups()) {
    const id = arn.sg(account, region, sg.groupId);
    sgNode.set(sg.groupId, id);
    nodes.push({
      id,
      type: "aws::ec2::security-group",
      name: sg.groupName ?? sg.groupId,
      account,
      region,
      parent: sg.vpcId ? (vpcNode.get(sg.vpcId) ?? regionId) : regionId,
      tags: sg.tags,
      // The rule engine evaluates exposure from these; shape is shared with
      // the Terraform adapter (see ingressAttribute in common/ingress.ts).
      attributes: { ingress: ingressAttribute(sg.ingress) },
    });
    // Record whether this SG exposes anything to the internet, and capture
    // SG-to-SG rules for the dataflow pass (who may reach this group, on what).
    for (const rule of sg.ingress) {
      const ports = portLabel(rule.fromPort, rule.toPort);
      if (isInternetFacing(rule.cidrs)) {
        // Carry the actual open CIDR (IPv4 or IPv6) instead of assuming v4 — an
        // ::/0 rule was previously mislabelled 0.0.0.0/0.
        const cidr =
          rule.cidrs.find((c) => c === "0.0.0.0/0" || c === "::/0") ??
          "0.0.0.0/0";
        sgInternetIngress.set(sg.groupId, { ports, cidr });
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
    const id = arn.inst(account, region, inst.instanceId);
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
      // Only emit when the SG node exists: the source must be the SG, never the
      // instance itself. The previous `source: sgId2 ?? id` fell back to the
      // instance, drawing a nonsensical instance→itself self-loop.
      if (exposed && sgId2) {
        edges.push({
          id: `e-net-${sgId}-${inst.instanceId}`,
          source: sgId2,
          target: id,
          relationship: "allows-ingress",
          lens: "network",
          attributes: {
            ports: exposed.ports,
            from: exposed.cidr,
            internetFacing: true,
          },
        });
      }
    }
  }

  // --- RDS -----------------------------------------------------------------
  for (const db of await client.dbInstances()) {
    const id = arn.db(account, region, db.dbInstanceIdentifier);
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
    const id = arn.fn(account, region, fn.functionName);
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

  }

  const accountNode = containers.account(account);
  if (doGlobal) {
    // --- IAM principals ------------------------------------------------------
    // Collect roles and users as principal nodes, then hand the assembled set to
    // the shared assume-role analysis pass (the brain). No edges are computed
    // inline: that is what keeps IAM correct in one place across every adapter.
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

  }

  // --- Dataflow analysis pass (SG reachability + explicit refs) ------------
  // Resolve Lambda env values that name an existing resource into references.
  // The matched value is never stored — only the resulting edge.
  const refTargets = nodes.filter((n) => !isContainer(n.type));
  const references: DataflowReference[] = [];
  for (const lambda of dfLambdas) {
    const seen = new Set<string>();
    for (const value of Object.values(lambda.env)) {
      if (typeof value !== "string" || value.length < 4) continue;
      for (const target of refTargets) {
        if (target.id === lambda.id || seen.has(target.id)) continue;
        // ARNs are specific enough to match as a substring; a bare resource
        // name (e.g. an RDS identifier) must appear as a delimited token so a
        // short identifier can't false-match inside an unrelated word
        // (`prod` inside `production-config`).
        const byArn = value.includes(target.id);
        const byName =
          target.type === "aws::rds::db-instance" &&
          mentionsToken(value, target.name);
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

  // --- Tag secret scan (parity with the Terraform adapter) -----------------
  // A plaintext secret can hide in a tag value on any resource. Redact it in
  // place so it never ships, and raise a finding — the live adapter previously
  // scanned only user-data and Lambda env vars, letting tag secrets through.
  for (const node of nodes) {
    const tagScan = scanRecord(node.tags);
    if (tagScan.found) {
      for (const key of tagScan.keys) node.tags[key] = "[redacted-secret]";
      findings.push(plaintextSecretFinding(node.id, "tags", tagScan.kinds));
    }
  }

  return {
    nodes: [...containers.nodes.values(), ...nodes],
    edges,
    findings,
    meta: {
      generatedAt: (opts.now?.() ?? new Date()).toISOString(),
      source: SOURCE,
      provider: "aws",
    },
  };
}

/**
 * True when `token` appears in `haystack` as a delimited run (bounded by a
 * non-alphanumeric character or the string ends), not merely as a substring.
 * Keeps name-based dataflow inference from firing on incidental substrings.
 */
function mentionsToken(haystack: string, token: string): boolean {
  if (token.length < 4) return false;
  const esc = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9])${esc}([^A-Za-z0-9]|$)`).test(haystack);
}

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
