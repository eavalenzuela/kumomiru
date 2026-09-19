import { z } from "zod";
import { FindingSchema, SeveritySchema } from "./schema.js";

/**
 * API-only schemas for persisted state. Deliberately NOT part of `GraphSchema`:
 * a Graph is a point-in-time snapshot, and lifecycle is what happens to a
 * finding *across* snapshots. The viewer and server validate these the way
 * they validate a Graph.
 */

export const FINDING_STATUSES = ["open", "resolved", "suppressed"] as const;
export const FindingStatusSchema = z.enum(FINDING_STATUSES);

/** A finding with its lifecycle, as stored and served. */
export const FindingRecordSchema = FindingSchema.extend({
  accountId: z.string(),
  status: FindingStatusSchema,
  firstSeenAt: z.string(),
  lastSeenAt: z.string(),
  resolvedAt: z.string().nullable(),
  /** Snapshot in which it was last observed. */
  lastSnapshotId: z.string(),
  suppressionId: z.string().nullable(),
});

export const RULE_RESULT_STATUSES = ["pass", "fail", "not-applicable", "not-assessed"] as const;
export const RuleResultStatusSchema = z.enum(RULE_RESULT_STATUSES);

/** One rule evaluated against one resource in one snapshot. */
export const RuleResultSchema = z.object({
  ruleId: z.string(),
  resourceId: z.string(),
  resourceType: z.string(),
  status: RuleResultStatusSchema,
});

/** Per-control roll-up for a framework. */
export const ControlStatusSchema = z.object({
  framework: z.string(),
  controlId: z.string(),
  title: z.string(),
  /** pass: every assessed resource passed; fail: any failed; not-assessed: nothing evaluated. */
  status: z.enum(["pass", "fail", "not-assessed"]),
  pass: z.number().int(),
  fail: z.number().int(),
  notAssessed: z.number().int(),
  ruleIds: z.array(z.string()),
  failingResourceIds: z.array(z.string()),
});

const ChangedNodeSchema = z.object({
  id: z.string(),
  type: z.string(),
  changedKeys: z.array(z.string()),
});

/** What changed between two snapshots of the same account. */
export const SnapshotDiffSchema = z.object({
  prevSnapshotId: z.string().nullable(),
  nextSnapshotId: z.string().nullable(),
  nodesAdded: z.array(z.object({ id: z.string(), type: z.string() })),
  nodesRemoved: z.array(z.object({ id: z.string(), type: z.string() })),
  nodesChanged: z.array(ChangedNodeSchema),
  edgesAdded: z.array(z.string()),
  edgesRemoved: z.array(z.string()),
  findingsNew: z.array(z.object({ id: z.string(), severity: SeveritySchema, kind: z.string() })),
  findingsResolved: z.array(z.object({ id: z.string(), severity: SeveritySchema, kind: z.string() })),
});

export type FindingStatus = z.infer<typeof FindingStatusSchema>;
export type FindingRecord = z.infer<typeof FindingRecordSchema>;
export type RuleResultStatus = z.infer<typeof RuleResultStatusSchema>;
export type RuleResult = z.infer<typeof RuleResultSchema>;
export type ControlStatus = z.infer<typeof ControlStatusSchema>;
export type SnapshotDiff = z.infer<typeof SnapshotDiffSchema>;
