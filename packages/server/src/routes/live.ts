import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  runLiveDiscovery,
  type AwsCredentials,
  type DiscoveryClientFactory,
} from "@kumomiru/adapters";
import { checkReferentialIntegrity } from "@kumomiru/graph";
import { makeSdkClient } from "../aws/sdkClient.js";
import { redactObject } from "../redact.js";

/**
 * Convert a thrown value into a plain, log-safe object: Error's message/name are
 * non-enumerable so they're surfaced explicitly, and any enumerable extras an
 * SDK error attaches (request config, headers, partial creds) are included so
 * `redactObject` can scrub their sensitive keys before they ever hit the log.
 */
function toLoggable(err: unknown): unknown {
  if (err instanceof Error) {
    // Spread first (enumerable SDK extras), then pin name/message — those are
    // non-enumerable on Error so the spread omits them.
    return { ...err, name: err.name, message: err.message };
  }
  return err;
}

/**
 * Body schema for live discovery. Credentials are accepted in the request body
 * (over TLS), used for exactly one run, and never stored. Short-lived STS
 * sessions (sessionToken present) are strongly preferred.
 */
const LiveBodySchema = z.object({
  accessKeyId: z.string().min(1),
  secretAccessKey: z.string().min(1),
  sessionToken: z.string().optional(),
  region: z.string().min(1),
});

/**
 * @param makeClient injectable discovery-client factory; defaults to the real
 * SDK-backed client. Tests pass a fake so no AWS or credentials are needed.
 */
export function registerLiveRoute(
  app: FastifyInstance,
  makeClient?: DiscoveryClientFactory,
): void {
  const clientFactory: DiscoveryClientFactory = makeClient ?? makeSdkClient;
  /**
   * POST /map/live
   * Body: { accessKeyId, secretAccessKey, sessionToken?, region }
   * Returns: a normalized Graph from live read-only discovery.
   *
   * The credential broker borrows the credentials for one run and scrubs them
   * afterward; this handler holds no reference once it returns.
   */
  app.post("/map/live", async (request, reply) => {
    const parsed = LiveBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({
        error: "invalid_credentials_body",
        message: "expected accessKeyId, secretAccessKey, region",
      });
    }

    const creds: AwsCredentials = parsed.data;
    if (!creds.sessionToken) {
      // Not an error, but worth telling the client: long-lived keys have a
      // larger blast radius than STS sessions.
      request.log.warn(
        "live discovery using long-lived credentials; prefer STS session tokens",
      );
    }

    try {
      const graph = await runLiveDiscovery(creds, clientFactory);
      const problems = checkReferentialIntegrity(graph);
      if (problems.length > 0) {
        return reply.status(422).send({ error: "graph_integrity", problems });
      }
      return graph;
    } catch (err) {
      // An SDK error can carry request context (headers, partial creds) on its
      // enumerable properties, which Fastify's path-based redaction does not
      // cover. Scrub it with the key-name matcher before logging.
      request.log.error(
        { err: redactObject(toLoggable(err)) },
        "live discovery failed",
      );
      return reply.status(502).send({
        error: "discovery_failed",
        message:
          err instanceof Error ? err.message : "live discovery failed",
      });
    }
  });
}
