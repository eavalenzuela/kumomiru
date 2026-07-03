import type { CloudNode, CloudEdge, Finding, Graph } from "@kumomiru/graph";
import type { Adapter } from "../contract.js";
import { Containers } from "../common/containers.js";
import {
  scanText,
  scanRecord,
  marker,
  plaintextSecretFinding,
} from "../common/sanitize.js";
import {
  analyzeDataflow,
  type DataflowMember,
  type DataflowIngress,
} from "../analysis/dataflow.js";
import type { IamAnalysisResult } from "../analysis/iam.js";
import { buildTerraformIam, type TfIamNode } from "./iam.js";
import { TfStateSchema, type TfState } from "./state-schema.js";
import { NODE_MAPPINGS, regionAccountFromAttrs } from "./mappings.js";

const SOURCE = "terraform-state";
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number | undefined =>
  typeof v === "number" ? v : undefined;
const arrOfStr = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

interface Built {
  node: CloudNode;
  /** raw value of attrs that other resources reference (the AWS id). */
  rawId: string;
  /** TF address "type.name". */
  address: string;
  /** original attribute bag, for the edge pass. */
  attrs: Record<string, unknown>;
}

/**
 * Terraform-state adapter. Zero credentials: input is parsed `.tfstate` JSON.
 * Produces containment + a first network-edge pass (IGW attachment, security
 * group membership, internet-facing ingress).
 */
export const terraformAdapter: Adapter<unknown> = {
  source: SOURCE,
  toGraph(input: unknown): Graph {
    const state: TfState = TfStateSchema.parse(input);
    const containers = new Containers();
    const built: Built[] = [];
    const byRawId = new Map<string, string>(); // aws id -> node id

    // -- pass 1: nodes ------------------------------------------------------
    for (const resource of state.resources) {
      if (resource.mode !== "managed") continue;
      const mapping = NODE_MAPPINGS[resource.type];
      if (!mapping) continue;

      for (const inst of resource.instances) {
        const attrs = inst.attributes;
        const { region, account } = regionAccountFromAttrs(attrs);
        const acct = account ?? "000000000000";
        const id = str(attrs["arn"]) || `tf:${resource.type}.${resource.name}`;
        const name = mapping.name(attrs) || resource.name;

        const node: CloudNode = {
          id,
          type: mapping.nodeType,
          name,
          account: acct,
          ...(region ? { region } : {}),
          tags: (attrs["tags"] as Record<string, string>) ?? {},
          attributes: mapping.attributes(attrs),
        };

        built.push({
          node,
          rawId: str(attrs["id"]),
          address: `${resource.type}.${resource.name}`,
          attrs,
        });
        if (node.id) byRawId.set(str(attrs["id"]), node.id);
      }
    }

    // -- pass 2: containment ------------------------------------------------
    for (const b of built) {
      const m = NODE_MAPPINGS[mappingKey(b)];
      const acct = b.node.account;
      let parent: string | undefined;
      const parentIdAttr = m?.parentIdAttr;
      if (parentIdAttr) {
        parent = byRawId.get(str(b.attrs[parentIdAttr]));
      }
      if (!parent) {
        if (m?.fallbackParent === "account" || !b.node.region) {
          parent = containers.account(acct);
        } else {
          parent = containers.region(acct, b.node.region);
        }
      }
      b.node.parent = parent;
    }

    // -- pass 3: network edges ---------------------------------------------
    const edges: CloudEdge[] = [];
    for (const b of built) {
      collectNetworkEdges(b, byRawId, edges);
    }

    // -- pass 4: secret detection ------------------------------------------
    // The same sanitization layer the live adapter uses (DESIGN.md §6B): scan
    // the free-form fields Terraform state carries (EC2 user-data, Lambda env
    // vars, tag values) for plaintext secrets, replace any value with a marker,
    // and raise a finding. Without this, tfstate — the locked first adapter —
    // produced zero findings even when secrets were sitting in the state file.
    const findings: Finding[] = [];
    for (const b of built) {
      collectSecrets(b, findings);
    }

    // -- pass 5: dataflow + internet exposure (SG ingress) ------------------
    // Parse security-group ingress from state to emit dataflow talks-to edges
    // (SG-to-SG reachability) and network internet-facing edges — parity with
    // the live adapter, via the same shared analyzeDataflow pass.
    collectDataflowEdges(built, edges);

    // -- pass 6: IAM assume-role analysis (the shared brain) ----------------
    // Feed the role/user set + their trust and inline identity policies to the
    // same analyzeAssumeRole pass the live adapter uses, so tfstate maps get
    // can-assume edges and external-can-assume findings.
    const iamNodes = collectIamNodes(built);
    let iam: IamAnalysisResult = { nodes: [], edges: [], findings: [] };
    if (iamNodes.length > 0) {
      const selfAccount = iamNodes[0]!.account;
      const accountNode = containers.account(selfAccount);
      iam = buildTerraformIam(state, iamNodes, selfAccount, accountNode);
      edges.push(...iam.edges);
      findings.push(...iam.findings);
    }

    const nodes = [
      ...containers.nodes.values(),
      ...built.map((b) => b.node),
      ...iam.nodes,
    ];
    return {
      nodes,
      edges,
      findings,
      meta: {
        generatedAt: new Date(0).toISOString(),
        source: SOURCE,
        provider: "aws",
      },
    };
  },
};

/** Project the built role/user nodes for the shared IAM analysis pass. */
function collectIamNodes(built: Built[]): TfIamNode[] {
  const out: TfIamNode[] = [];
  for (const b of built) {
    const kind: "role" | "user" | null =
      b.node.type === "aws::iam::role"
        ? "role"
        : b.node.type === "aws::iam::user"
          ? "user"
          : null;
    if (!kind) continue;
    out.push({
      id: b.node.id,
      account: b.node.account,
      name: b.node.name,
      rawId: b.rawId,
      kind,
      attrs: b.attrs,
    });
  }
  return out;
}

/** Human-readable port (or range) for an SG ingress block. */
function portRange(rule: Record<string, unknown>): string {
  const from = num(rule["from_port"]);
  const to = num(rule["to_port"]);
  if (from === undefined && to === undefined) return "all";
  if (from === to) return String(from);
  return `${from ?? 0}-${to ?? 65535}`;
}

/**
 * Parse security-group ingress and instance membership into the dataflow and
 * internet-exposure edges, mirroring the live adapter. SG-to-SG rules become
 * `talks-to` dataflow edges via the shared analyzeDataflow pass; a rule open to
 * 0.0.0.0/0 (or ::/0) becomes a red network allows-ingress edge per member.
 */
function collectDataflowEdges(built: Built[], edges: CloudEdge[]): void {
  // Raw SG id -> node id, and SG name -> raw id (ingress sources may name a SG
  // by either).
  const sgNodeByRawId = new Map<string, string>();
  const sgIdByName = new Map<string, string>();
  for (const b of built) {
    if (mappingKey(b) !== "aws_security_group") continue;
    const rawId = str(b.attrs["id"]);
    if (rawId) sgNodeByRawId.set(rawId, b.node.id);
    const name = str(b.attrs["name"]);
    if (name && rawId) sgIdByName.set(name, rawId);
  }
  const normalizeSource = (ref: string): string =>
    ref.startsWith("sg-") ? ref : (sgIdByName.get(ref) ?? ref);

  const members: DataflowMember[] = [];
  for (const b of built) {
    if (mappingKey(b) !== "aws_instance") continue;
    const groupIds = arrOfStr(b.attrs["vpc_security_group_ids"]);
    if (groupIds.length) members.push({ id: b.node.id, groupIds });
  }

  const ingress: DataflowIngress[] = [];
  const internetSG = new Map<string, { ports: string; cidr: string }>();
  for (const b of built) {
    if (mappingKey(b) !== "aws_security_group") continue;
    const rawId = str(b.attrs["id"]);
    const rules = Array.isArray(b.attrs["ingress"])
      ? (b.attrs["ingress"] as Array<Record<string, unknown>>)
      : [];
    for (const rule of rules) {
      const ports = portRange(rule);
      const cidrs = [
        ...arrOfStr(rule["cidr_blocks"]),
        ...arrOfStr(rule["ipv6_cidr_blocks"]),
      ];
      const openCidr = cidrs.find((c) => c === "0.0.0.0/0" || c === "::/0");
      if (openCidr) internetSG.set(rawId, { ports, cidr: openCidr });
      const sources = arrOfStr(rule["security_groups"]).map(normalizeSource);
      if (sources.length) {
        ingress.push({ groupId: rawId, sourceGroupIds: sources, ports });
      }
    }
  }

  // Internet-facing network edges: SG -> each member instance it protects.
  for (const m of members) {
    for (const rawSg of m.groupIds) {
      const exposed = internetSG.get(rawSg);
      const sgNodeId = sgNodeByRawId.get(rawSg);
      if (exposed && sgNodeId) {
        edges.push({
          id: `e-net-${rawSg}-${m.id}`,
          source: sgNodeId,
          target: m.id,
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

  edges.push(...analyzeDataflow({ members, ingress, references: [] }).edges);
}

function mappingKey(b: Built): string {
  // address is "type.name"; the type is everything before the first dot.
  const dot = b.address.indexOf(".");
  return dot === -1 ? b.address : b.address.slice(0, dot);
}

/** Lambda env vars in tfstate live at `environment[0].variables` (a block list). */
function lambdaEnvVars(attrs: Record<string, unknown>): Record<string, unknown> {
  const env = attrs["environment"];
  const block = Array.isArray(env) ? env[0] : env;
  const vars =
    block && typeof block === "object"
      ? (block as Record<string, unknown>)["variables"]
      : undefined;
  return vars && typeof vars === "object"
    ? (vars as Record<string, unknown>)
    : {};
}

/**
 * Scan a resource's secret-prone fields and, on a hit, mark the node (never the
 * value) and emit a plaintext-secret finding. Mirrors the live adapter so the
 * two ingestion paths surface the same risk.
 */
function collectSecrets(b: Built, findings: Finding[]): void {
  const a = b.attrs;

  const userData = str(a["user_data"]);
  if (userData) {
    const r = scanText(userData);
    if (r.found) {
      b.node.attributes["userDataSecret"] = marker(r.kinds[0]!);
      findings.push(plaintextSecretFinding(b.node.id, "EC2 user-data", r.kinds));
    }
  }

  const envScan = scanRecord(lambdaEnvVars(a));
  if (envScan.found) {
    b.node.attributes["envSecret"] = marker(envScan.kinds[0]!);
    findings.push(
      plaintextSecretFinding(b.node.id, "environment variables", envScan.kinds),
    );
  }

  const tagScan = scanRecord(b.node.tags);
  if (tagScan.found) {
    // A secret hid in a tag value — redact it in place so it never ships.
    for (const key of tagScan.keys) b.node.tags[key] = "[redacted-secret]";
    findings.push(plaintextSecretFinding(b.node.id, "tags", tagScan.kinds));
  }
}

function collectNetworkEdges(
  b: Built,
  byRawId: Map<string, string>,
  edges: CloudEdge[],
): void {
  const type = mappingKey(b);

  // IGW attached to its VPC.
  if (type === "aws_internet_gateway") {
    const vpc = byRawId.get(str(b.attrs["vpc_id"]));
    if (vpc) {
      edges.push({
        id: `e-igw-${b.node.id}`,
        source: b.node.id,
        target: vpc,
        relationship: "attached-to",
        lens: "network",
        attributes: {},
      });
    }
  }

  // Instance membership in security groups.
  if (type === "aws_instance") {
    const sgs = Array.isArray(b.attrs["vpc_security_group_ids"])
      ? (b.attrs["vpc_security_group_ids"] as unknown[])
      : [];
    for (const sg of sgs) {
      const sgNode = byRawId.get(str(sg));
      if (sgNode) {
        edges.push({
          id: `e-sgm-${sgNode}-${b.node.id}`,
          source: sgNode,
          target: b.node.id,
          relationship: "protects",
          lens: "network",
          attributes: {},
        });
      }
    }
  }
}
