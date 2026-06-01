import type { z } from "zod";
import type {
  LensSchema,
  SeveritySchema,
  CloudNodeSchema,
  CloudEdgeSchema,
  FindingSchema,
  GraphMetaSchema,
  GraphSchema,
} from "./schema.js";

/**
 * Static types for the normalized cloud graph.
 *
 * These are DERIVED from the Zod schemas in `schema.ts` — that file is the
 * single source of truth. Both the discovery backend and the Cytoscape viewer
 * import these, so a field change in the schema breaks compilation in both
 * places. No drift, ever.
 */

export type Lens = z.infer<typeof LensSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type CloudNode = z.infer<typeof CloudNodeSchema>;
export type CloudEdge = z.infer<typeof CloudEdgeSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type GraphMeta = z.infer<typeof GraphMetaSchema>;
export type Graph = z.infer<typeof GraphSchema>;
