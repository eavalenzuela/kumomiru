import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { FRAMEWORKS, SEVERITIES, FINDING_STATUSES, type Framework } from "@kumomiru/graph";
import type { Database } from "@kumomiru/db";
import { CATALOGUES, controlStatuses, defaultRegistry, isCheckRule } from "@kumomiru/rules";

/**
 * Findings, suppressions, rules/controls metadata, compliance roll-up, and
 * snapshot diffs (docs/cspm-roadmap.md Phase 2). Read paths hit the
 * database; the rule registry and catalogues come straight from
 * @kumomiru/rules so what the API describes is what the worker evaluates.
 */

const FindingsQuery = z.object({
  accountId: z.string().regex(/^\d{12}$/).optional(),
  status: z.enum(FINDING_STATUSES).optional(),
  severity: z.enum(SEVERITIES).optional(),
  ruleId: z.string().optional(),
  framework: z.enum(FRAMEWORKS).optional(),
  control: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(5000).optional(),
});

const SuppressionBody = z.object({
  ruleId: z.string().min(1),
  resourcePattern: z.string().min(1),
  accountId: z.string().regex(/^\d{12}$/).optional(),
  reason: z.string().min(3).max(2000),
  expiresAt: z.string().datetime().optional(),
});

const ComplianceQuery = z.object({
  framework: z.enum(FRAMEWORKS),
  accountId: z.string().regex(/^\d{12}$/).optional(),
});

function paramId(request: FastifyRequest): string {
  return (request.params as { id: string }).id;
}

export function registerFindingRoutes(app: FastifyInstance, db: Database): void {
  const registry = defaultRegistry();

  app.get("/findings", async (request, reply) => {
    const q = FindingsQuery.safeParse(request.query);
    if (!q.success) return reply.status(400).send({ error: "invalid_query", issues: q.error.issues });
    const { framework, control, ...rest } = q.data;
    if ((framework && !control) || (control && !framework)) {
      return reply.status(400).send({ error: "invalid_query", message: "framework and control go together" });
    }
    return db.findings.list({
      ...rest,
      ...(framework && control ? { control: { framework, id: control } } : {}),
    });
  });

  app.get("/findings/summary", async (request) => {
    const q = (request.query as { accountId?: string }) ?? {};
    return { open: db.findings.openCounts(q.accountId) };
  });

  app.get("/findings/:id", async (request, reply) => {
    const f = db.findings.get(paramId(request));
    if (!f) return reply.status(404).send({ error: "not_found" });
    return f;
  });

  // --- suppressions ---------------------------------------------------------

  app.get("/suppressions", async (request) => {
    const all = (request.query as { all?: string })?.all;
    return db.suppressions.list({ includeInactive: all === "1" || all === "true" });
  });

  app.post("/suppressions", async (request, reply) => {
    const parsed = SuppressionBody.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: "invalid_suppression", issues: parsed.error.issues });
    if (!registry.get(parsed.data.ruleId)) {
      return reply.status(400).send({ error: "invalid_suppression", message: `unknown rule ${parsed.data.ruleId}` });
    }
    const s = db.suppressions.create(parsed.data);
    // Take effect on currently open findings right away, not at the next scan.
    db.findings.applySuppressions(db.suppressions.list(), new Date().toISOString());
    return reply.status(201).send(s);
  });

  app.delete("/suppressions/:id", async (request, reply) => {
    if (!db.suppressions.revoke(paramId(request))) return reply.status(404).send({ error: "not_found" });
    db.findings.applySuppressions(db.suppressions.list(), new Date().toISOString());
    return reply.status(204).send();
  });

  // --- rules / controls -----------------------------------------------------

  app.get("/rules", async () =>
    registry.list().map((r) => ({
      id: r.id,
      version: r.version,
      title: r.title,
      severity: r.severity,
      kind: r.kind,
      resourceTypes: isCheckRule(r) ? r.resourceTypes : [],
      requires: isCheckRule(r) ? r.requires : [],
      adopts: r.adopts ?? null,
      controls: r.controls,
      remediation: r.remediation,
    })),
  );

  app.get("/controls", async (request, reply) => {
    const fw = (request.query as { framework?: string })?.framework;
    const list = fw ? CATALOGUES.filter((c) => c.framework === fw) : CATALOGUES;
    if (fw && list.length === 0) return reply.status(400).send({ error: "unknown_framework" });
    return list.map((c) => ({ framework: c.framework, name: c.name, version: c.version, controls: c.controls }));
  });

  // --- compliance -------------------------------------------------------------

  /**
   * Per-control status for a framework, from the latest snapshot of each
   * account (or one account). `overall` rolls every account's results
   * together; `accounts` breaks them out.
   */
  app.get("/compliance", async (request, reply) => {
    const q = ComplianceQuery.safeParse(request.query);
    if (!q.success) return reply.status(400).send({ error: "invalid_query", issues: q.error.issues });
    const framework: Framework = q.data.framework;
    const accounts = q.data.accountId
      ? [db.accounts.get(q.data.accountId)].filter((a): a is NonNullable<typeof a> => a !== null)
      : db.accounts.list();
    if (q.data.accountId && accounts.length === 0) return reply.status(404).send({ error: "not_found" });

    const perAccount = accounts.map((a) => {
      const snap = db.snapshots.latestForAccount(a.id);
      const results = snap ? db.ruleResults.forSnapshot(snap.id) : [];
      return {
        accountId: a.id,
        name: a.name,
        snapshotId: snap?.id ?? null,
        generatedAt: snap?.generatedAt ?? null,
        controls: controlStatuses(framework, results, registry),
      };
    });
    const allResults = accounts.flatMap((a) => {
      const snap = db.snapshots.latestForAccount(a.id);
      return snap ? db.ruleResults.forSnapshot(snap.id) : [];
    });
    return {
      framework,
      catalogueVersion: CATALOGUES.find((c) => c.framework === framework)?.version ?? null,
      overall: controlStatuses(framework, allResults, registry),
      accounts: perAccount,
    };
  });

  // --- diffs ------------------------------------------------------------------

  app.get("/snapshots/:id/diff", async (request, reply) => {
    const d = db.diffs.get(paramId(request));
    if (!d) return reply.status(404).send({ error: "not_found" });
    return d;
  });
}
