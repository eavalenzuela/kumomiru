import Fastify, {
  type FastifyInstance,
  type FastifyRequest,
} from "fastify";
import {
  terraformAdapter,
  type DiscoveryClientFactory,
} from "@kumomiru/adapters";
import {
  sampleGraph,
  checkReferentialIntegrity,
  redactGraph,
  type Graph,
} from "@kumomiru/graph";
import { REDACT_PATHS } from "./redact.js";
import { registerLiveRoute, wantsRedacted } from "./routes/live.js";
import { registerPolicyRoute } from "./routes/policy.js";

export interface BuildAppOptions {
  /** Pass false in tests to silence logging. */
  logger?: boolean;
  /** Cap on accepted request body size (bytes). Exports can be large. */
  bodyLimit?: number;
  /**
   * Override the discovery-client factory for /map/live. Defaults to the real
   * SDK-backed client; tests inject a fake so no AWS/credentials are needed.
   */
  discoveryClientFactory?: DiscoveryClientFactory;
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
  // `?redacted=1` strips data values (DESIGN.md §6B) via the shared redactGraph,
  // so the server can hand out a share-safe map, not just the viewer.
  app.get(
    "/sample",
    async (request: FastifyRequest): Promise<Graph> =>
      wantsRedacted(request) ? redactGraph(sampleGraph) : sampleGraph,
  );

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

    return wantsRedacted(request) ? redactGraph(graph) : graph;
  });

  // POST /map/live — live read-only AWS discovery (in-memory creds, dropped
  // after the run).
  registerLiveRoute(app, opts.discoveryClientFactory);

  // GET /policy/least-privilege — the exact read-only policy a scan role needs.
  registerPolicyRoute(app);

  return app;
}
