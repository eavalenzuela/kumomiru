import type { Graph } from "@kumomiru/graph";

/**
 * Every ingestion adapter is a pure, side-effect-free function from some source
 * input to a normalized Graph. Adapters NEVER read credentials from globals or
 * env directly — anything credential-bearing receives a provider (see the live
 * adapter, later) so the same code can run server-side now and as a local CLI
 * agent later.
 *
 * The Terraform-state adapter is the simplest case: no credentials at all, the
 * input is just parsed file contents.
 */
export interface Adapter<TInput> {
  /** Stable id used as Graph.meta.source, e.g. "terraform-state". */
  readonly source: string;
  toGraph(input: TInput): Graph;
}
