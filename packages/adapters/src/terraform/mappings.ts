import { parseArn } from "./arn.js";
import { ingressAttribute, type IngressRule } from "../common/ingress.js";

/**
 * Per-Terraform-type mapping rules. Each entry knows how to turn a TF resource
 * instance's attribute bag into the fields of a kumomiru node, plus which raw
 * AWS id of *another* resource it is contained by (resolved to a parent node id
 * in a second pass).
 *
 * `parentIdAttr` names the attribute holding the containing resource's raw AWS
 * id (e.g. an aws_subnet's `vpc_id`). If absent, the resource is parented to its
 * region (or account, for global services like IAM).
 */
export interface NodeMapping {
  /** kumomiru node type, e.g. "aws::ec2::vpc". */
  nodeType: string;
  /** Human name; falls back to the TF resource name when this returns "". */
  name(attrs: Record<string, unknown>): string;
  /** Attribute holding the parent's raw AWS id, if containment is resource-based. */
  parentIdAttr?: string;
  /** Container to fall back to when there is no parentIdAttr. */
  fallbackParent: "region" | "account";
  /** Curated, non-secret attributes to carry onto the node. */
  attributes(attrs: Record<string, unknown>): Record<string, unknown>;
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number | undefined =>
  typeof v === "number" ? v : undefined;
const bool = (v: unknown): boolean | undefined =>
  typeof v === "boolean" ? v : undefined;

/** Drop undefined values so node attributes stay clean. */
function compact(o: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) if (v !== undefined) out[k] = v;
  return out;
}

export const NODE_MAPPINGS: Record<string, NodeMapping> = {
  aws_vpc: {
    nodeType: "aws::ec2::vpc",
    name: (a) => str(a["tags"] && (a["tags"] as Record<string, unknown>)["Name"]),
    fallbackParent: "region",
    attributes: (a) => compact({ cidrBlock: str(a["cidr_block"]) }),
  },
  aws_subnet: {
    nodeType: "aws::ec2::subnet",
    name: (a) => str((a["tags"] as Record<string, unknown> | undefined)?.["Name"]),
    parentIdAttr: "vpc_id",
    fallbackParent: "region",
    attributes: (a) =>
      compact({
        cidrBlock: str(a["cidr_block"]),
        availabilityZone: str(a["availability_zone"]),
        mapPublicIpOnLaunch: bool(a["map_public_ip_on_launch"]),
      }),
  },
  aws_internet_gateway: {
    nodeType: "aws::ec2::internet-gateway",
    name: (a) => str((a["tags"] as Record<string, unknown> | undefined)?.["Name"]),
    parentIdAttr: "vpc_id",
    fallbackParent: "region",
    attributes: () => ({}),
  },
  aws_instance: {
    nodeType: "aws::ec2::instance",
    name: (a) => str((a["tags"] as Record<string, unknown> | undefined)?.["Name"]),
    parentIdAttr: "subnet_id",
    fallbackParent: "region",
    attributes: (a) =>
      compact({
        instanceType: str(a["instance_type"]),
        publicIp: str(a["public_ip"]),
        privateIp: str(a["private_ip"]),
      }),
  },
  aws_db_instance: {
    nodeType: "aws::rds::db-instance",
    name: (a) => str(a["identifier"]),
    fallbackParent: "region",
    attributes: (a) =>
      compact({
        engine: str(a["engine"]),
        port: num(a["port"]),
        publiclyAccessible: bool(a["publicly_accessible"]),
      }),
  },
  aws_lambda_function: {
    nodeType: "aws::lambda::function",
    name: (a) => str(a["function_name"]),
    fallbackParent: "region",
    attributes: (a) =>
      compact({ runtime: str(a["runtime"]), handler: str(a["handler"]) }),
  },
  aws_dynamodb_table: {
    nodeType: "aws::dynamodb::table",
    name: (a) => str(a["name"]),
    fallbackParent: "region",
    attributes: () => ({}),
  },
  aws_secretsmanager_secret: {
    nodeType: "aws::secretsmanager::secret",
    name: (a) => str(a["name"]),
    fallbackParent: "region",
    // We list the secret but never resolve its value.
    attributes: () => ({ secretPresent: true, valueResolved: false }),
  },
  aws_iam_role: {
    nodeType: "aws::iam::role",
    name: (a) => str(a["name"]),
    fallbackParent: "account",
    attributes: () => ({}),
  },
  aws_iam_user: {
    nodeType: "aws::iam::user",
    name: (a) => str(a["name"]) || str(a["user_name"]),
    fallbackParent: "account",
    attributes: () => ({}),
  },
  aws_s3_bucket: {
    nodeType: "aws::s3::bucket",
    name: (a) => str(a["bucket"]) || str(a["id"]),
    fallbackParent: "region",
    attributes: () => ({}),
  },
  aws_kms_key: {
    nodeType: "aws::kms::key",
    name: (a) => str(a["description"]) || str(a["key_id"]) || str(a["id"]),
    fallbackParent: "region",
    attributes: (a) =>
      compact({
        manager: "CUSTOMER",
        enabled: bool(a["is_enabled"]) ?? true,
        rotationEnabled: bool(a["enable_key_rotation"]) ?? false,
      }),
  },
  aws_ebs_volume: {
    nodeType: "aws::ec2::volume",
    name: (a) => str((a["tags"] as Record<string, unknown> | undefined)?.["Name"]) || str(a["id"]),
    fallbackParent: "region",
    attributes: (a) => compact({ encrypted: bool(a["encrypted"]) ?? false, sizeGiB: num(a["size"]) }),
  },
  aws_cloudtrail: {
    nodeType: "aws::cloudtrail::trail",
    name: (a) => str(a["name"]),
    fallbackParent: "account",
    attributes: (a) =>
      compact({
        isMultiRegion: bool(a["is_multi_region_trail"]) ?? false,
        isLogging: bool(a["enable_logging"]) ?? true,
        logFileValidationEnabled: bool(a["enable_log_file_validation"]) ?? false,
        managementEvents: true,
        kmsEncrypted: Boolean(str(a["kms_key_id"])),
      }),
  },
  aws_security_group: {
    nodeType: "aws::ec2::security-group",
    name: (a) => str(a["name"]),
    parentIdAttr: "vpc_id",
    fallbackParent: "region",
    attributes: (a) => ({ ingress: terraformIngress(a["ingress"]) }),
  },
};

/**
 * Terraform's `ingress` blocks → the shared IngressRule shape. `protocol` "-1"
 * means all; from/to 0 with -1 is "all ports".
 */
function terraformIngress(raw: unknown): IngressRule[] {
  if (!Array.isArray(raw)) return [];
  return ingressAttribute(
    (raw as Array<Record<string, unknown>>).map((r) => ({
      ...(num(r["from_port"]) !== undefined ? { fromPort: num(r["from_port"]) } : {}),
      ...(num(r["to_port"]) !== undefined ? { toPort: num(r["to_port"]) } : {}),
      ...(str(r["protocol"]) ? { ipProtocol: str(r["protocol"]) } : {}),
      cidrs: [
        ...(Array.isArray(r["cidr_blocks"]) ? (r["cidr_blocks"] as unknown[]) : []),
        ...(Array.isArray(r["ipv6_cidr_blocks"]) ? (r["ipv6_cidr_blocks"] as unknown[]) : []),
      ].filter((c): c is string => typeof c === "string"),
      sourceGroupIds: (Array.isArray(r["security_groups"]) ? (r["security_groups"] as unknown[]) : []).filter(
        (g): g is string => typeof g === "string",
      ),
    })),
  );
}

/** region/account derived from a resource's arn when not given on attributes. */
export function regionAccountFromAttrs(attrs: Record<string, unknown>): {
  region?: string;
  account?: string;
} {
  const arn = parseArn(str(attrs["arn"]));
  return {
    region: arn?.region || undefined,
    account: arn?.account || undefined,
  };
}
