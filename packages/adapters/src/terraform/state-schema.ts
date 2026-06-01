import { z } from "zod";

/**
 * A deliberately loose schema for Terraform state (format version 4). We only
 * validate the envelope we rely on for traversal; each resource's `attributes`
 * bag is provider-specific and kept as an open record, interpreted per-type by
 * the mapping layer.
 */

export const TfInstanceSchema = z.object({
  // index_key present on counted/for_each resources; we don't need it for ids.
  attributes: z.record(z.unknown()).default({}),
  // dependencies are fully-qualified addresses like "aws_subnet.public".
  dependencies: z.array(z.string()).default([]),
});

export const TfResourceSchema = z.object({
  // "managed" | "data" — we only map managed resources.
  mode: z.string(),
  type: z.string(),
  name: z.string(),
  provider: z.string().default(""),
  instances: z.array(TfInstanceSchema).default([]),
});

export const TfStateSchema = z.object({
  version: z.number(),
  terraform_version: z.string().optional(),
  resources: z.array(TfResourceSchema).default([]),
});

export type TfInstance = z.infer<typeof TfInstanceSchema>;
export type TfResource = z.infer<typeof TfResourceSchema>;
export type TfState = z.infer<typeof TfStateSchema>;
