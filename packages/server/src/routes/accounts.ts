import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { Cron } from "croner";
import { redactGraph } from "@kumomiru/graph";
import type { Database } from "@kumomiru/db";

import { wantsRedacted } from "./live.js";

/**
 * Manual account registration + scan control (docs/cspm-roadmap.md Phase 1).
 * The server only ever writes `accounts` and enqueues `scans`; the worker
 * claims and runs them and writes snapshots. Nothing here touches AWS.
 */

const AccountBody = z.object({
  id: z.string().regex(/^\d{12}$/, "12-digit AWS account id"),
  name: z.string().min(1).max(200),
  roleArn: z
    .string()
    .regex(/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@\/-]+$/, "IAM role ARN"),
  externalId: z.string().min(2).max(1224).optional(),
  regions: z.array(z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d$/)).min(1).optional(),
  scheduleCron: z.string().optional(),
  status: z.enum(["pending", "active", "inactive"]).optional(),
});

const ScanBody = z
  .object({ trigger: z.enum(["manual", "verify"]).default("manual") })
  .default({ trigger: "manual" });

function paramId(request: FastifyRequest): string {
  return (request.params as { id: string }).id;
}

export function registerAccountRoutes(app: FastifyInstance, db: Database): void {
  app.get("/accounts", async () =>
    db.accounts.list().map((a) => ({
      ...a,
      latestSnapshot: db.snapshots.latestForAccount(a.id),
      activeScan: db.scans.active(a.id),
      lastScan: db.scans.listForAccount(a.id, 1)[0] ?? null,
    })),
  );

  app.post("/accounts", async (request, reply) => {
    const parsed = AccountBody.safeParse(request.body);
    if (!parsed.success) {
      return reply
        .status(400)
        .send({ error: "invalid_account", issues: parsed.error.issues });
    }
    const body = parsed.data;
    // The role must live in the account being registered.
    if (body.roleArn.split(":")[4] !== body.id) {
      return reply.status(400).send({
        error: "invalid_account",
        message: "roleArn must belong to the registered account id",
      });
    }
    if (body.scheduleCron) {
      try {
        new Cron(body.scheduleCron, { timezone: "UTC" });
      } catch {
        return reply
          .status(400)
          .send({ error: "invalid_account", message: "scheduleCron is not a valid cron expression" });
      }
    }
    const existed = db.accounts.get(body.id) !== null;
    const account = db.accounts.upsert({
      id: body.id,
      name: body.name,
      roleArn: body.roleArn,
      externalId: body.externalId ?? null,
      regions: body.regions ?? null,
      ...(body.scheduleCron ? { scheduleCron: body.scheduleCron } : {}),
      ...(body.status ? { status: body.status } : {}),
    });
    return reply.status(existed ? 200 : 201).send(account);
  });

  app.get("/accounts/:id", async (request, reply) => {
    const account = db.accounts.get(paramId(request));
    if (!account) return reply.status(404).send({ error: "not_found" });
    return {
      ...account,
      latestSnapshot: db.snapshots.latestForAccount(account.id),
      activeScan: db.scans.active(account.id),
    };
  });

  app.delete("/accounts/:id", async (request, reply) => {
    if (!db.accounts.remove(paramId(request))) {
      return reply.status(404).send({ error: "not_found" });
    }
    return reply.status(204).send();
  });

  /** The most recent stored map for the account; `?redacted=1` strips values. */
  app.get("/accounts/:id/latest", async (request, reply) => {
    const id = paramId(request);
    if (!db.accounts.get(id)) return reply.status(404).send({ error: "not_found" });
    const latest = db.snapshots.latestForAccount(id);
    const graph = latest ? db.snapshots.getGraph(latest.id) : null;
    if (!graph) {
      return reply
        .status(404)
        .send({ error: "no_snapshot", message: "no completed scan for this account yet" });
    }
    return wantsRedacted(request) ? redactGraph(graph) : graph;
  });

  /** Queue a scan (or a role verification). Idempotent while one is active. */
  app.post("/accounts/:id/scans", async (request, reply) => {
    const id = paramId(request);
    if (!db.accounts.get(id)) return reply.status(404).send({ error: "not_found" });
    const parsed = ScanBody.safeParse(request.body ?? undefined);
    if (!parsed.success) {
      return reply.status(400).send({ error: "invalid_scan_request" });
    }
    const scan = db.scans.enqueue(id, parsed.data.trigger);
    return reply.status(202).send(scan);
  });

  app.get("/accounts/:id/scans", async (request, reply) => {
    const id = paramId(request);
    if (!db.accounts.get(id)) return reply.status(404).send({ error: "not_found" });
    return db.scans.listForAccount(id);
  });

  app.get("/accounts/:id/snapshots", async (request, reply) => {
    const id = paramId(request);
    if (!db.accounts.get(id)) return reply.status(404).send({ error: "not_found" });
    return db.snapshots.listForAccount(id);
  });

  app.get("/scans/:id", async (request, reply) => {
    const scan = db.scans.get(paramId(request));
    if (!scan) return reply.status(404).send({ error: "not_found" });
    return scan;
  });

  app.get("/snapshots/:id", async (request, reply) => {
    const snap = db.snapshots.get(paramId(request));
    if (!snap) return reply.status(404).send({ error: "not_found" });
    return snap;
  });

  app.get("/snapshots/:id/graph", async (request, reply) => {
    const graph = db.snapshots.getGraph(paramId(request));
    if (!graph) return reply.status(404).send({ error: "not_found" });
    return wantsRedacted(request) ? redactGraph(graph) : graph;
  });
}
