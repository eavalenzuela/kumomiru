import type { FastifyInstance } from "fastify";
import { LEAST_PRIVILEGE_POLICY } from "@kumomiru/aws";

/**
 * GET /policy/least-privilege — serve the read-only IAM policy a scan role
 * needs. The policy itself lives in @kumomiru/aws, generated from the actions
 * the SDK client declares, so this route can never drift from the calls.
 */
export function registerPolicyRoute(app: FastifyInstance): void {
  app.get("/policy/least-privilege", async (_request, reply) => {
    reply.header(
      "content-disposition",
      'attachment; filename="kumomiru-readonly-policy.json"',
    );
    return LEAST_PRIVILEGE_POLICY;
  });
}
