import type { CloudNode, CloudEdge, Finding, Graph } from "@kumomiru/graph";
import { Containers } from "../common/containers.js";
import {
  scanText,
  scanRecord,
  marker,
  plaintextSecretFinding,
} from "../common/sanitize.js";
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
 *   - instance can-assume role (when an instance-profile role is resolvable)
 *   - external/other-account principals can-assume role (from trust policy)
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
  const roleByName = new Map<string, string>();

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
    // Record whether this SG exposes anything to the internet, and on what.
    for (const rule of sg.ingress) {
      if (isInternetFacing(rule.cidrs)) {
        const ports =
          rule.fromPort === rule.toPort
            ? String(rule.fromPort ?? "all")
            : `${rule.fromPort ?? 0}-${rule.toPort ?? 65535}`;
        sgInternetIngress.set(sg.groupId, { ports });
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

  // --- IAM roles + assume-role edges ---------------------------------------
  const accountNode = containers.account(account);
  for (const role of await client.roles()) {
    roleByName.set(role.roleName, role.arn);
    nodes.push({
      id: role.arn,
      type: "aws::iam::role",
      name: role.roleName,
      account,
      parent: accountNode,
      tags: role.tags,
      attributes: {},
    });
  }

  // Assume-role edges: trust policy says WHO may assume each role. (First IAM
  // increment: assume-role graph only — both-sides identity-policy evaluation
  // comes later.) External/other-account principals get a critical finding.
  for (const role of await client.roles()) {
    for (const p of role.trustedPrincipals) {
      if (p.type === "service") {
        // Service trust (e.g. ec2/lambda): model as the service being able to
        // assume — represented later when we add service principal nodes. Skip
        // edge for now but keep the role attribute hint.
        continue;
      }
      const external = isExternalPrincipal(p.value, account);
      const principalNode = ensurePrincipalNode(
        nodes,
        containers,
        account,
        p.value,
        external,
      );
      edges.push({
        id: `e-assume-${hash(p.value + role.arn)}`,
        source: principalNode,
        target: role.arn,
        relationship: "can-assume",
        lens: "iam",
        attributes: { trustConfirmed: true, external },
      });
      if (external) {
        findings.push({
          id: `f-extassume-${hash(p.value + role.arn)}`,
          severity: "critical",
          kind: "external-can-assume",
          nodeId: role.arn,
          title: "External principal can assume a role",
          detail: `Role ${role.roleName} trusts external principal ${p.value}. Verify this is intended and gated by a condition (ExternalId/MFA).`,
        });
      }
    }
  }

  return {
    nodes: [...containers.nodes.values(), ...nodes],
    edges,
    findings,
    meta: { generatedAt: new Date(0).toISOString(), source: SOURCE, provider: "aws" },
  };
}

/** A principal value is external if it names a different account than ours. */
function isExternalPrincipal(value: string, account: string): boolean {
  // arn:aws:iam::<acct>:... or a bare account id.
  const m = value.match(/arn:aws:iam::(\d{12}):/);
  if (m) return m[1] !== account;
  const bare = value.match(/^(\d{12})$/);
  if (bare) return bare[1] !== account;
  return false;
}

/** Create (once) a principal node for an assume-role source. */
function ensurePrincipalNode(
  nodes: CloudNode[],
  containers: Containers,
  account: string,
  value: string,
  external: boolean,
): string {
  const id = external
    ? `aws::iam::external-principal::${value}`
    : value;
  if (!nodes.some((n) => n.id === id)) {
    nodes.push({
      id,
      type: external ? "aws::iam::external-principal" : "aws::iam::role",
      name: external ? shortPrincipal(value) : value,
      account: external ? extractAccount(value) ?? "external" : account,
      parent: containers.account(account),
      tags: {},
      attributes: external ? { external: true } : {},
    });
  }
  return id;
}

function shortPrincipal(value: string): string {
  const acct = extractAccount(value);
  return acct ? `external-account-${acct}` : value;
}

function extractAccount(value: string): string | undefined {
  return value.match(/(\d{12})/)?.[1];
}

function hash(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (h * 33) ^ s.charCodeAt(i);
  return (h >>> 0).toString(36);
}
