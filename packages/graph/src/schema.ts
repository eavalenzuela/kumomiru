import { z } from "zod";

/**
 * The normalized cloud graph — runtime schema (source of truth).
 *
 * Every ingestion adapter (Terraform state, AWS Config, live AWS API) and every
 * analysis pass (IAM reachability, secret detection) produces data validated by
 * these schemas. The TypeScript types in `types.ts` are derived from here via
 * `z.infer`, so the static and runtime views can never drift.
 */

/** The three lenses are edge subsets over one shared node set. */
export const LENSES = ["network", "iam", "dataflow"] as const;
export const LensSchema = z.enum(LENSES);

export const SEVERITIES = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
] as const;
export const SeveritySchema = z.enum(SEVERITIES);

/**
 * A resource. Containment is expressed with `parent`, which drives Cytoscape
 * compound nodes: account -> region -> VPC -> AZ -> subnet -> resource.
 *
 * `attributes` is always sanitized — raw secret values are never stored here;
 * the sanitization layer replaces them with `{ secretPresent: true, ... }`.
 */
export const CloudNodeSchema = z.object({
  /** ARN or other stable URN. */
  id: z.string().min(1),
  /** Namespaced type, e.g. "aws::ec2::instance". */
  type: z.string().min(1),
  name: z.string(),
  account: z.string(),
  region: z.string().optional(),
  /** id of the containing node, if any. */
  parent: z.string().optional(),
  tags: z.record(z.string()).default({}),
  attributes: z.record(z.unknown()).default({}),
});

/**
 * A relationship. `lens` is what powers the viewer's lens toggle — switching a
 * lens is just filtering edges by this field.
 */
export const CloudEdgeSchema = z.object({
  id: z.string().min(1),
  source: z.string().min(1),
  target: z.string().min(1),
  /** e.g. contains | routes-to | can-assume | allows-ingress | reads-from */
  relationship: z.string().min(1),
  lens: LensSchema,
  attributes: z.record(z.unknown()).default({}),
});

/** Compliance frameworks a rule can map to. */
export const FRAMEWORKS = ["fsbp", "nist-csf-2"] as const;
export const FrameworkSchema = z.enum(FRAMEWORKS);

/** A reference to one control in one framework, e.g. FSBP `EC2.13`. */
export const ControlRefSchema = z.object({
  framework: FrameworkSchema,
  id: z.string().min(1),
});

/** Operator guidance. The tool never applies it. */
export const RemediationSchema = z.object({
  text: z.string(),
  cli: z.string().optional(),
  terraform: z.string().optional(),
});

/** Where a finding came from. */
export const FINDING_SOURCES = ["native", "securityhub", "accessanalyzer", "drift"] as const;
export const FindingSourceSchema = z.enum(FINDING_SOURCES);

/**
 * A security observation surfaced to the user. Produced by the sanitization
 * layer ("plaintext secret detected"), the IAM pass ("external principal can
 * assume admin"), and — since the CSPM conversion — the rule engine.
 *
 * Everything after `detail` is optional so ad-hoc graphs, the sample, and the
 * viewer keep working unchanged. Lifecycle (open/resolved/suppressed) is NOT
 * here: a Graph is a point-in-time snapshot; lifecycle lives in
 * `FindingRecord` (lifecycle.ts) and the database.
 */
export const FindingSchema = z.object({
  id: z.string().min(1),
  severity: SeveritySchema,
  /** e.g. "plaintext-secret" | "external-can-assume" | "sg-open-ssh" */
  kind: z.string().min(1),
  /** The resource this finding is about, if applicable. */
  nodeId: z.string().optional(),
  title: z.string(),
  detail: z.string(),
  /** Rule registry id, e.g. "ec2.sg-unrestricted-ssh". */
  ruleId: z.string().optional(),
  source: FindingSourceSchema.optional(),
  controls: z.array(ControlRefSchema).optional(),
  remediation: RemediationSchema.optional(),
  /** Survives node deletion for resolved findings. */
  resourceType: z.string().optional(),
  /** Sanitized values the rule saw. Dropped by redactGraph. */
  evidence: z.record(z.unknown()).optional(),
  /** Security Hub finding ARN / Access Analyzer finding id. */
  externalId: z.string().optional(),
  observedAt: z.string().optional(),
});

export const GraphMetaSchema = z.object({
  /** ISO 8601 timestamp of when the graph was generated. */
  generatedAt: z.string(),
  /** What produced it, e.g. "terraform-state" | "aws-live" | "sample". */
  source: z.string(),
  provider: z.literal("aws"),
  // --- Set by the scheduled-scan pipeline (all optional; ad-hoc graphs and the
  // sample omit them, and the viewer never depends on them).
  /** The scanned account, when the graph covers exactly one. */
  accountId: z.string().optional(),
  /** Regions the scan covered, when it was a multi-region merge. */
  regions: z.array(z.string()).optional(),
  /** Persisted snapshot id, once stored. */
  snapshotId: z.string().optional(),
  /** The scan run that produced it, once stored. */
  scanId: z.string().optional(),
});

export const GraphSchema = z.object({
  nodes: z.array(CloudNodeSchema),
  edges: z.array(CloudEdgeSchema),
  findings: z.array(FindingSchema).default([]),
  meta: GraphMetaSchema,
});
