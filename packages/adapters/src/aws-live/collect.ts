import type { CloudNode, CloudEdge, Finding } from "@kumomiru/graph";
import type { Containers } from "../common/containers.js";
import type { DataflowIngress, DataflowMember } from "../analysis/dataflow.js";
import type { AnalyzedPrincipal } from "../analysis/iam.js";
import type { AccessResource } from "../analysis/resourceAccess.js";
import type { DiscoveryClient } from "./client.js";

/**
 * Shared state one discovery run threads through its collectors. Collectors
 * append nodes/edges/findings and record the cross-references the analysis
 * passes need; they never compute IAM or dataflow edges themselves.
 */
export interface CollectContext {
  client: DiscoveryClient;
  account: string;
  region: string;
  partition: string;
  arn: ArnHelpers;
  containers: Containers;
  /** Region container id (regional passes) or account id (global pass). */
  regionId: string;
  accountNode: string;
  nodes: CloudNode[];
  edges: CloudEdge[];
  findings: Finding[];
  /** Raw AWS id → node id, for wiring edges. */
  index: {
    vpc: Map<string, string>;
    subnet: Map<string, string>;
    sg: Map<string, string>;
    instance: Map<string, string>;
    kmsKey: Map<string, string>;
    bucket: Map<string, string>;
    /** IGW raw id → node id, NAT raw id → node id (for route targets). */
    igw: Map<string, string>;
    nat: Map<string, string>;
    /** Internet-facing SG ingress, from the network collector. */
    internet: Map<string, { ports: string; cidr: string }>;
  };
  /** Inputs for the dataflow pass. */
  df: {
    members: DataflowMember[];
    ingress: DataflowIngress[];
    lambdas: Array<{ id: string; env: Record<string, string> }>;
  };
  /** Inputs for the IAM passes. */
  principals: AnalyzedPrincipal[];
  resources: AccessResource[];
}

export interface ArnHelpers {
  vpc(acct: string, region: string, id: string): string;
  subnet(acct: string, region: string, id: string): string;
  igw(acct: string, region: string, id: string): string;
  sg(acct: string, region: string, id: string): string;
  inst(acct: string, region: string, id: string): string;
  volume(acct: string, region: string, id: string): string;
  snapshot(acct: string, region: string, id: string): string;
  db(acct: string, region: string, id: string): string;
  fn(acct: string, region: string, id: string): string;
  routeTable(acct: string, region: string, id: string): string;
  nat(acct: string, region: string, id: string): string;
  peering(acct: string, region: string, id: string): string;
  endpoint(acct: string, region: string, id: string): string;
  nacl(acct: string, region: string, id: string): string;
  launchTemplate(acct: string, region: string, id: string): string;
}

/**
 * ARN helpers for stable node ids, bound to the account's partition so ids
 * match the real ARNs IAM returns (`arn:aws-us-gov:...` in GovCloud, etc.).
 */
export function arnHelpers(partition: string): ArnHelpers {
  const p = partition;
  return {
    vpc: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:vpc/${id}`,
    subnet: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:subnet/${id}`,
    igw: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:internet-gateway/${id}`,
    sg: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:security-group/${id}`,
    inst: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:instance/${id}`,
    volume: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:volume/${id}`,
    snapshot: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:snapshot/${id}`,
    db: (acct, region, id) => `arn:${p}:rds:${region}:${acct}:db:${id}`,
    fn: (acct, region, id) => `arn:${p}:lambda:${region}:${acct}:function:${id}`,
    routeTable: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:route-table/${id}`,
    nat: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:natgateway/${id}`,
    peering: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:vpc-peering-connection/${id}`,
    endpoint: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:vpc-endpoint/${id}`,
    nacl: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:network-acl/${id}`,
    launchTemplate: (acct, region, id) => `arn:${p}:ec2:${region}:${acct}:launch-template/${id}`,
  };
}

export function nameFromTags(tags: Record<string, string>, fallback: string): string {
  return tags["Name"] ?? fallback;
}

/** True when an ingress rule is open to the internet. */
export function isInternetFacing(cidrs: string[]): boolean {
  return cidrs.includes("0.0.0.0/0") || cidrs.includes("::/0");
}

/** Human-readable port (or range) for an SG rule's from/to ports. */
export function portLabel(fromPort?: number, toPort?: number): string {
  if (fromPort === toPort) return String(fromPort ?? "all");
  return `${fromPort ?? 0}-${toPort ?? 65535}`;
}

/** Register a KMS `encrypted-by` edge when the key is known. */
export function encryptedByEdge(ctx: CollectContext, sourceId: string, kmsKeyRef: string | undefined): void {
  if (!kmsKeyRef) return;
  // A key may be referenced by ARN, key id, or alias; the index holds all three.
  const keyNode = ctx.index.kmsKey.get(kmsKeyRef);
  if (!keyNode) return;
  ctx.edges.push({
    id: `e-enc-${sourceId}`,
    source: sourceId,
    target: keyNode,
    relationship: "encrypted-by",
    lens: "dataflow",
    attributes: {},
  });
}
