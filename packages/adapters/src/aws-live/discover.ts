import { isContainer, type CloudEdge, type CloudNode, type Finding, type Graph } from "@kumomiru/graph";
import { Containers } from "../common/containers.js";
import { plaintextSecretFinding, scanRecord } from "../common/sanitize.js";
import { analyzeAssumeRole } from "../analysis/iam.js";
import { analyzeResourceAccess } from "../analysis/resourceAccess.js";
import { analyzeDataflow, type DataflowReference } from "../analysis/dataflow.js";
import { OPTIONAL_CAPABILITIES, type DiscoveryClient } from "./client.js";
import { arnHelpers, type CollectContext } from "./collect.js";
import { collectNetwork } from "./collectors/network.js";
import { collectCompute } from "./collectors/compute.js";
import { collectDatabase } from "./collectors/database.js";
import { collectServerless } from "./collectors/serverless.js";
import { collectStorage } from "./collectors/storage.js";
import { collectSecurity } from "./collectors/security.js";
import { collectIam } from "./collectors/iam.js";
import { collectRouting } from "./collectors/routing.js";
import { collectLoadBalancers } from "./collectors/loadbalancers.js";
import { collectContainers } from "./collectors/containers.js";
import { collectMessaging } from "./collectors/messaging.js";
import { collectData } from "./collectors/data.js";
import { collectScaling } from "./collectors/scaling.js";
import { collectEdgeGlobal, collectEdgeRegional } from "./collectors/edge.js";

const SOURCE = "aws-live";

/**
 * What a full live discovery always collects — the base of the rule engine's
 * `requires` vocabulary. Optional collectors add the names in
 * `OPTIONAL_CAPABILITIES`; a graph's `meta.capabilities` is the authoritative
 * list for the scan that produced it.
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

const REGIONAL_BASE = [
  "ec2:vpc", "ec2:subnet", "ec2:internet-gateway", "ec2:security-group", "ec2:instance",
  "rds:db-instance", "lambda:function", "secretsmanager:secret",
];
const GLOBAL_CAPS = new Set<string>([
  "iam:role", "iam:user",
  OPTIONAL_CAPABILITIES.accountSummary, OPTIONAL_CAPABILITIES.credentialReport, OPTIONAL_CAPABILITIES.cloudTrails,
  OPTIONAL_CAPABILITIES.cloudFrontDistributions,
]);

/**
 * Which slice of the account a single `discoverGraph` call collects.
 *
 * - `all` (default): everything, one region — the ad-hoc `/map/live` path.
 * - `regional`: region-scoped resources only. No IAM principals, no IAM pass.
 * - `global`: IAM roles/users, account-level facts, CloudTrail, and the IAM
 *   passes. The scheduled scanner runs this once per account and then
 *   `mergeGraphs` it with one `regional` graph per region.
 */
export type DiscoverScope = "all" | "regional" | "global";

export interface DiscoverOptions {
  /** Clock for `meta.generatedAt`; injectable for deterministic tests. */
  now?: () => Date;
  scope?: DiscoverScope;
}

/**
 * The core discovery pass: read everything from the (read-only) client and
 * normalize into a Graph. Pure with respect to the client — no SDK, no creds
 * here — so it is fully unit-testable with a fake client.
 *
 * Collection is split by service into `collectors/`; each appends nodes,
 * network/dataflow inputs, and the principal/resource facts the analysis
 * passes consume. IAM is NOT computed inline: `analyzeAssumeRole` and
 * `analyzeResourceAccess` (the shared brain, used by every adapter) run after
 * collection over the assembled sets.
 *
 * Secrets discovered in user-data / env vars / tags are detected, redacted to
 * markers, and raised as findings. Secrets Manager secrets are listed as
 * nodes; values are never fetched.
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
  const containers = new Containers();
  const accountNode = containers.account(account);
  // A global-only pass must not synthesize a region container it never fills.
  const regionId = doRegional ? containers.region(account, region) : accountNode;

  const ctx: CollectContext = {
    client,
    account,
    region,
    partition,
    arn: arnHelpers(partition),
    containers,
    regionId,
    accountNode,
    nodes: [],
    edges: [],
    findings: [],
    index: {
      vpc: new Map(), subnet: new Map(), sg: new Map(), instance: new Map(), kmsKey: new Map(), bucket: new Map(),
      igw: new Map(), nat: new Map(), internet: new Map(),
    },
    df: { members: [], ingress: [], lambdas: [] },
    principals: [],
    resources: [],
  };

  if (doRegional) {
    const internet = await collectNetwork(ctx);
    await collectRouting(ctx);
    await collectCompute(ctx, internet);
    await collectScaling(ctx);
    await collectDatabase(ctx);
    await collectServerless(ctx);
    // KMS keys before buckets/secrets/tables so encrypted-by edges can resolve.
    await collectSecurity(ctx);
    await collectStorage(ctx);
    await collectMessaging(ctx);
    await collectData(ctx);
    await collectContainers(ctx);
    await collectLoadBalancers(ctx);
    await collectEdgeRegional(ctx);
  }
  if (doGlobal) {
    await collectIam(ctx);
    await collectEdgeGlobal(ctx);
  }

  const { nodes, edges, findings } = ctx;

  // --- IAM analysis passes (assume-role; resource policies) ----------------
  if (doGlobal) {
    const iam = analyzeAssumeRole(ctx.principals, account, accountNode);
    nodes.push(...iam.nodes);
    edges.push(...iam.edges);
    findings.push(...iam.findings);
  }
  if (ctx.resources.length > 0) {
    // Resource policies are regional facts; the principals they name are
    // resolved against whatever principal set this pass has (all of them in
    // an `all` run; none in a `regional` run — then only public/external
    // grants, which need no principal lookup, produce edges and findings).
    const access = analyzeResourceAccess(ctx.principals, ctx.resources, account, accountNode);
    mergeExternalNodes(nodes, access.nodes);
    edges.push(...access.edges);
    findings.push(...access.findings);
  }

  // --- Dataflow analysis pass (SG reachability + explicit refs) ------------
  const refTargets = nodes.filter((n) => !isContainer(n.type));
  const references: DataflowReference[] = [];
  for (const lambda of ctx.df.lambdas) {
    const seen = new Set<string>();
    for (const value of Object.values(lambda.env)) {
      if (typeof value !== "string" || value.length < 4) continue;
      for (const target of refTargets) {
        if (target.id === lambda.id || seen.has(target.id)) continue;
        const byArn = value.includes(target.id);
        const byName = target.type === "aws::rds::db-instance" && mentionsToken(value, target.name);
        if (byArn || byName) {
          seen.add(target.id);
          references.push({ from: lambda.id, to: target.id, relationship: dataflowRelationship(target.type), via: "lambda-env" });
        }
      }
    }
  }
  edges.push(...analyzeDataflow({ members: ctx.df.members, ingress: ctx.df.ingress, references }).edges);

  // --- Tag secret scan ------------------------------------------------------
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
      capabilities: capabilitiesFor(client, scope),
    },
  };
}

/** Capabilities this run had, by scope. */
function capabilitiesFor(client: DiscoveryClient, scope: DiscoverScope): string[] {
  const declared = new Set(client.capabilities?.() ?? []);
  for (const [method, cap] of Object.entries(OPTIONAL_CAPABILITIES)) {
    if (typeof (client as unknown as Record<string, unknown>)[method] === "function") declared.add(cap);
  }
  const out = new Set<string>();
  if (scope !== "global") {
    for (const c of REGIONAL_BASE) out.add(c);
    for (const c of declared) if (!GLOBAL_CAPS.has(c)) out.add(c);
  }
  if (scope !== "regional") {
    out.add("iam:role");
    if (client.users) out.add("iam:user");
    for (const c of declared) if (GLOBAL_CAPS.has(c)) out.add(c);
  }
  return [...out].sort();
}

/** External-principal nodes may be synthesized by both IAM passes; keep one per id. */
function mergeExternalNodes(nodes: CloudNode[], extra: CloudNode[]): void {
  const have = new Set(nodes.map((n) => n.id));
  for (const n of extra) if (!have.has(n.id)) { nodes.push(n); have.add(n.id); }
}

/**
 * True when `token` appears in `haystack` as a delimited run (bounded by a
 * non-alphanumeric character or the string ends), not merely as a substring.
 */
function mentionsToken(haystack: string, token: string): boolean {
  if (token.length < 4) return false;
  const esc = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9])${esc}([^A-Za-z0-9]|$)`).test(haystack);
}

/** Dataflow edge relationship for a referenced resource type. */
function dataflowRelationship(type: string): string {
  switch (type) {
    case "aws::secretsmanager::secret":
    case "aws::dynamodb::table":
    case "aws::s3::bucket":
    case "aws::ssm::parameter":
    case "aws::sqs::queue":
      return "reads-from";
    case "aws::sns::topic":
      return "publishes-to";
    case "aws::rds::db-instance":
    case "aws::rds::db-cluster":
      return "connects-to";
    default:
      return "references";
  }
}

export type { CloudEdge, Finding };
