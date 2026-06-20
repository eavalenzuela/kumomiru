import type { CloudNode, CloudEdge, Finding, Graph } from "@kumomiru/graph";
import type { Adapter } from "../contract.js";
import { Containers } from "../common/containers.js";
import {
  scanText,
  scanRecord,
  marker,
  plaintextSecretFinding,
} from "../common/sanitize.js";
import { TfStateSchema, type TfState } from "./state-schema.js";
import { NODE_MAPPINGS, regionAccountFromAttrs } from "./mappings.js";

const SOURCE = "terraform-state";
const str = (v: unknown): string => (typeof v === "string" ? v : "");

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

    const nodes = [...containers.nodes.values(), ...built.map((b) => b.node)];
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
