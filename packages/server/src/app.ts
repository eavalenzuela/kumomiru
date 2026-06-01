import Fastify, { type FastifyInstance } from "fastify";
import { terraformAdapter } from "@kumomiru/adapters";
import {
  sampleGraph,
  checkReferentialIntegrity,
  type Graph,
} from "@kumomiru/graph";
import { REDACT_PATHS } from "./redact.js";

export interface BuildAppOptions {
  /** Pass false in tests to silence logging. */
  logger?: boolean;
  /** Cap on accepted request body size (bytes). Exports can be large. */
  bodyLimit?: number;
}

/**
 * Builds the Fastify app. Kept separate from `listen()` so tests can drive it
 * via `app.inject()` without binding a port.
 *
 * Credential discipline: this server never persists request bodies. The
 * Terraform path carries no credentials; when the live-API path lands, its
 * credentials live only for the duration of one request handler and are dropped
 * when it returns (see the live route, later). Redaction is configured up front.
 */
export function buildApp(opts: BuildAppOptions = {}): FastifyInstance {
  const app = Fastify({
    bodyLimit: opts.bodyLimit ?? 25 * 1024 * 1024,
    logger:
      opts.logger === false
        ? false
        : { redact: { paths: REDACT_PATHS, censor: "[REDACTED]" } },
  });

  app.get("/health", async () => ({ status: "ok" }));

  // Zero-setup data source for the viewer: the hand-authored sample graph.
  app.get("/sample", async (): Promise<Graph> => sampleGraph);

  /**
   * POST /map/terraform
   * Body: a parsed Terraform state object (the .tfstate JSON).
   * Returns: a normalized Graph. No credentials involved; nothing is stored.
   */
  app.post("/map/terraform", async (request, reply) => {
    let graph: Graph;
    try {
      graph = terraformAdapter.toGraph(request.body);
    } catch (err) {
      return reply.status(400).send({
        error: "invalid_terraform_state",
        message: err instanceof Error ? err.message : "could not parse state",
      });
    }

    const problems = checkReferentialIntegrity(graph);
    if (problems.length > 0) {
      // The adapter built a structurally broken graph — surface it rather than
      // shipping a map that won't render correctly.
      return reply
        .status(422)
        .send({ error: "graph_integrity", problems });
    }

    return graph;
  });

  return app;
}
