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
import type { Database } from "@kumomiru/db";
import { REDACT_PATHS } from "./redact.js";
import { registerLiveRoute, wantsRedacted } from "./routes/live.js";
import { registerPolicyRoute } from "./routes/policy.js";
import { registerAccountRoutes } from "./routes/accounts.js";
import { registerFindingRoutes } from "./routes/findings.js";
import { registerOnboardingRoutes } from "./routes/onboarding.js";
import { registerAuth, registerNoAuth, type AuthOptions } from "./auth/index.js";

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
  /**
   * The shared database (accounts, scans, snapshots). When absent the account
   * and snapshot routes are not registered and the server behaves as the
   * stateless ad-hoc mapper it was before Phase 1.
   */
  db?: Database;
  /**
   * Whether to expose the ad-hoc ingestion routes (`POST /map/terraform`,
   * `POST /map/live` with pasted credentials). Defaults to on outside
   * production (`NODE_ENV !== "production"`); the `KUMOMIRU_ADHOC_INGEST`
   * environment variable overrides it in `server.ts`.
   */
  adhocIngest?: boolean;
  /**
   * OIDC single sign-on. When absent, the server is open (no login, every
   * caller is anonymous and unrestricted) and `GET /auth/me` says so — fine
   * for local use; never for a shared deployment. Requires `db`.
   */
  auth?: AuthOptions;
}

/** Resolve the ad-hoc flag from an explicit option, else the environment. */
export function adhocIngestDefault(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env["KUMOMIRU_ADHOC_INGEST"];
  if (v === "1" || v === "true") return true;
  if (v === "0" || v === "false") return false;
  return env["NODE_ENV"] !== "production";
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
export async function buildApp(opts: BuildAppOptions = {}): Promise<FastifyInstance> {
  const app = Fastify({
    bodyLimit: opts.bodyLimit ?? 25 * 1024 * 1024,
    logger:
      opts.logger === false
        ? false
        : { redact: { paths: REDACT_PATHS, censor: "[REDACTED]" } },
  });

  app.get("/health", async () => ({ status: "ok" }));

  // Auth is registered first so its onRequest guard covers every route below.
  if (opts.auth) {
    if (!opts.db) throw new Error("auth requires a database");
    await registerAuth(app, opts.db, opts.auth);
  } else {
    registerNoAuth(app);
  }

  // Zero-setup data source for the viewer: the hand-authored sample graph.
  // `?redacted=1` strips data values (DESIGN.md §6B) via the shared redactGraph,
  // so the server can hand out a share-safe map, not just the viewer.
  app.get(
    "/sample",
    async (request: FastifyRequest): Promise<Graph> =>
      wantsRedacted(request) ? redactGraph(sampleGraph) : sampleGraph,
  );

  const adhoc = opts.adhocIngest ?? adhocIngestDefault();

  /**
   * POST /map/terraform
   * Body: a parsed Terraform state object (the .tfstate JSON).
   * Returns: a normalized Graph. No credentials involved; nothing is stored.
   */
  if (adhoc) app.post("/map/terraform", async (request, reply) => {
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
  // after the run). Ad-hoc only: scheduled scans never take pasted keys.
  if (adhoc) registerLiveRoute(app, opts.discoveryClientFactory);

  // Accounts, scans, snapshots — the persisted, scheduled path — and the
  // posture layer over it: findings, suppressions, rules, compliance, diffs.
  if (opts.db) {
    registerAccountRoutes(app, opts.db);
    registerFindingRoutes(app, opts.db);
    registerOnboardingRoutes(app, opts.db);
  }

  // GET /policy/least-privilege — the exact read-only policy a scan role needs.
  registerPolicyRoute(app);

  return app;
}
