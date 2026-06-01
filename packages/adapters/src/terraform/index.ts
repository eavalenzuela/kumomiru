import type { CloudNode, CloudEdge, Graph } from "@kumomiru/graph";
import type { Adapter } from "../contract.js";
import { TfStateSchema, type TfState } from "./state-schema.js";
import { NODE_MAPPINGS, regionAccountFromAttrs } from "./mappings.js";

const SOURCE = "terraform-state";
const str = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * Builds container nodes (account, region) on demand and dedupes them, so the
 * containment chain account -> region -> resource always exists even though
 * Terraform state has no explicit account/region resources.
 */
class Containers {
  readonly nodes = new Map<string, CloudNode>();

  account(account: string): string {
    const id = `aws::account::${account}`;
    if (!this.nodes.has(id)) {
      this.nodes.set(id, {
        id,
        type: "aws::account",
        name: account,
        account,
        tags: {},
        attributes: {},
      });
    }
    return id;
  }

  region(account: string, region: string): string {
    const id = `aws::region::${account}::${region}`;
    if (!this.nodes.has(id)) {
      this.nodes.set(id, {
        id,
        type: "aws::region",
        name: region,
        account,
        region,
        parent: this.account(account),
        tags: {},
        attributes: {},
      });
    }
    return id;
  }
}

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

    const nodes = [...containers.nodes.values(), ...built.map((b) => b.node)];
    return {
      nodes,
      edges,
      findings: [],
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
