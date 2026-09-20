import { randomUUID } from "node:crypto";
import type BetterSqlite3 from "better-sqlite3";
import type {
  Finding,
  FindingRecord,
  Framework,
  RuleResult,
  Severity,
  SnapshotDiff,
} from "@kumomiru/graph";

import type {
  ControlRecord,
  DiffRepo,
  FindingFilter,
  FindingRepo,
  MetadataRepo,
  NewSuppression,
  ReconcileSummary,
  RuleMeta,
  RuleResultRepo,
  SuppressionRecord,
  SuppressionRepo,
} from "./repository.js";

// --- suppression matching ---------------------------------------------------

function globToRegExp(pattern: string): RegExp {
  const esc = pattern.replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === "*" ? ".*" : `\\${c}`));
  return new RegExp(`^${esc}$`);
}

/** The first active suppression matching a finding, if any. */
export function matchSuppression(
  f: { ruleId?: string | undefined; nodeId?: string | undefined; accountId: string },
  suppressions: readonly SuppressionRecord[],
  now: string,
): SuppressionRecord | null {
  if (!f.ruleId) return null;
  for (const s of suppressions) {
    if (s.ruleId !== f.ruleId) continue;
    if (s.revokedAt) continue;
    if (s.expiresAt && s.expiresAt <= now) continue;
    if (s.accountId && s.accountId !== f.accountId) continue;
    const rid = f.nodeId ?? "";
    if (s.resourcePattern === "*" || s.resourcePattern === rid) return s;
    if (s.resourcePattern.includes("*") && globToRegExp(s.resourcePattern).test(rid)) return s;
  }
  return null;
}

// --- findings ---------------------------------------------------------------

interface FindingRow {
  id: string;
  account_id: string;
  rule_id: string | null;
  source: string;
  severity: string;
  kind: string;
  resource_id: string | null;
  resource_type: string | null;
  title: string;
  detail: string;
  controls_json: string;
  remediation_json: string | null;
  evidence_json: string | null;
  external_id: string | null;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  last_snapshot_id: string;
  suppression_id: string | null;
}

function toRecord(r: FindingRow): FindingRecord {
  return {
    id: r.id,
    accountId: r.account_id,
    severity: r.severity as Severity,
    kind: r.kind,
    title: r.title,
    detail: r.detail,
    ...(r.rule_id ? { ruleId: r.rule_id } : {}),
    source: r.source as FindingRecord["source"],
    ...(r.resource_id ? { nodeId: r.resource_id } : {}),
    ...(r.resource_type ? { resourceType: r.resource_type } : {}),
    controls: JSON.parse(r.controls_json) as FindingRecord["controls"],
    ...(r.remediation_json ? { remediation: JSON.parse(r.remediation_json) as FindingRecord["remediation"] } : {}),
    ...(r.evidence_json ? { evidence: JSON.parse(r.evidence_json) as Record<string, unknown> } : {}),
    ...(r.external_id ? { externalId: r.external_id } : {}),
    status: r.status as FindingRecord["status"],
    firstSeenAt: r.first_seen_at,
    lastSeenAt: r.last_seen_at,
    resolvedAt: r.resolved_at,
    lastSnapshotId: r.last_snapshot_id,
    suppressionId: r.suppression_id,
  };
}

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export function findingRepo(db: BetterSqlite3.Database): FindingRepo {
  const get = db.prepare("SELECT * FROM findings WHERE id = ?");
  const insert = db.prepare(`
    INSERT INTO findings (id, account_id, rule_id, source, severity, kind, resource_id,
      resource_type, title, detail, controls_json, remediation_json, evidence_json,
      external_id, status, first_seen_at, last_seen_at, resolved_at, last_snapshot_id,
      suppression_id)
    VALUES (@id, @account_id, @rule_id, @source, @severity, @kind, @resource_id,
      @resource_type, @title, @detail, @controls_json, @remediation_json, @evidence_json,
      @external_id, @status, @first_seen_at, @last_seen_at, NULL, @last_snapshot_id,
      @suppression_id)`);
  const refresh = db.prepare(`
    UPDATE findings SET severity = @severity, title = @title, detail = @detail,
      controls_json = @controls_json, remediation_json = @remediation_json,
      evidence_json = @evidence_json, resource_type = COALESCE(@resource_type, resource_type),
      status = @status, last_seen_at = @last_seen_at, resolved_at = NULL,
      last_snapshot_id = @last_snapshot_id, suppression_id = @suppression_id
    WHERE id = @id`);
  const unresolvedFor = db.prepare(
    "SELECT id FROM findings WHERE account_id = ? AND status IN ('open','suppressed')",
  );
  const resolve = db.prepare(
    "UPDATE findings SET status = 'resolved', resolved_at = ?, suppression_id = NULL WHERE id = ?",
  );
  const setStatus = db.prepare(
    "UPDATE findings SET status = ?, suppression_id = ? WHERE id = ?",
  );
  const unresolvedAll = db.prepare(
    "SELECT * FROM findings WHERE status IN ('open','suppressed')",
  );

  const reconcileTx = db.transaction(
    (input: Parameters<FindingRepo["reconcile"]>[0]): ReconcileSummary => {
      const summary: ReconcileSummary = { opened: [], reopened: [], resolved: [], suppressed: [], unchanged: 0 };
      const seen = new Set<string>();
      for (const f of input.findings) {
        seen.add(f.id);
        const sup = matchSuppression({ ...f, accountId: input.accountId }, input.suppressions, input.observedAt);
        const status = sup ? "suppressed" : "open";
        const common = {
          id: f.id,
          severity: f.severity,
          title: f.title,
          detail: f.detail,
          controls_json: JSON.stringify(f.controls ?? []),
          remediation_json: f.remediation ? JSON.stringify(f.remediation) : null,
          evidence_json: f.evidence ? JSON.stringify(f.evidence) : null,
          resource_type: f.resourceType ?? null,
          status,
          last_seen_at: input.observedAt,
          last_snapshot_id: input.snapshotId,
          suppression_id: sup?.id ?? null,
        };
        const existing = get.get(f.id) as FindingRow | undefined;
        if (!existing) {
          insert.run({
            ...common,
            account_id: input.accountId,
            rule_id: f.ruleId ?? null,
            source: f.source ?? "native",
            kind: f.kind,
            resource_id: f.nodeId ?? null,
            external_id: f.externalId ?? null,
            first_seen_at: input.observedAt,
          });
          (sup ? summary.suppressed : summary.opened).push(f.id);
        } else {
          refresh.run(common);
          if (existing.status === "resolved") summary.reopened.push(f.id);
          else summary.unchanged++;
        }
      }
      for (const row of unresolvedFor.all(input.accountId) as { id: string }[]) {
        if (seen.has(row.id)) continue;
        resolve.run(input.observedAt, row.id);
        summary.resolved.push(row.id);
      }
      return summary;
    },
  );

  const applyTx = db.transaction((suppressions: readonly SuppressionRecord[], now: string) => {
    for (const r of unresolvedAll.all() as FindingRow[]) {
      const sup = matchSuppression(
        { ruleId: r.rule_id ?? undefined, nodeId: r.resource_id ?? undefined, accountId: r.account_id },
        suppressions,
        now,
      );
      const want = sup ? "suppressed" : "open";
      if (want !== r.status || (sup?.id ?? null) !== r.suppression_id) {
        setStatus.run(want, sup?.id ?? null, r.id);
      }
    }
  });

  return {
    reconcile: (input) => reconcileTx(input),
    get: (id) => {
      const r = get.get(id) as FindingRow | undefined;
      return r ? toRecord(r) : null;
    },
    list: (filter: FindingFilter = {}) => {
      const where: string[] = [];
      const params: unknown[] = [];
      if (filter.accountId) { where.push("account_id = ?"); params.push(filter.accountId); }
      if (filter.status) { where.push("status = ?"); params.push(filter.status); }
      if (filter.severity) { where.push("severity = ?"); params.push(filter.severity); }
      if (filter.ruleId) { where.push("rule_id = ?"); params.push(filter.ruleId); }
      if (filter.source) { where.push("source = ?"); params.push(filter.source); }
      if (filter.control) {
        // controls_json is a small array; a substring match on the serialized
        // object is exact enough for {"framework":"x","id":"y"} pairs.
        where.push("controls_json LIKE ?");
        params.push(`%${JSON.stringify({ framework: filter.control.framework, id: filter.control.id })}%`);
      }
      const sql = `SELECT * FROM findings ${where.length ? "WHERE " + where.join(" AND ") : ""}
        ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                 last_seen_at DESC
        LIMIT ?`;
      params.push(filter.limit ?? 500);
      return (db.prepare(sql).all(...params) as FindingRow[]).map(toRecord);
    },
    openCounts: (accountId) => {
      const rows = (accountId
        ? db.prepare("SELECT severity, COUNT(*) AS n FROM findings WHERE status = 'open' AND account_id = ? GROUP BY severity").all(accountId)
        : db.prepare("SELECT severity, COUNT(*) AS n FROM findings WHERE status = 'open' GROUP BY severity").all()) as { severity: Severity; n: number }[];
      const out = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
      for (const r of rows) out[r.severity] = r.n;
      return out;
    },
    applySuppressions: (suppressions, now) => applyTx(suppressions, now),
  };
}

// --- rule results / diffs ---------------------------------------------------

export function ruleResultRepo(db: BetterSqlite3.Database): RuleResultRepo {
  const del = db.prepare("DELETE FROM rule_results WHERE snapshot_id = ?");
  const ins = db.prepare(
    "INSERT INTO rule_results (snapshot_id, rule_id, resource_id, resource_type, status) VALUES (?, ?, ?, ?, ?)",
  );
  const sel = db.prepare(
    "SELECT rule_id, resource_id, resource_type, status FROM rule_results WHERE snapshot_id = ?",
  );
  const replaceTx = db.transaction((snapshotId: string, results: readonly RuleResult[]) => {
    del.run(snapshotId);
    for (const r of results) ins.run(snapshotId, r.ruleId, r.resourceId, r.resourceType, r.status);
  });
  return {
    replaceForSnapshot: (snapshotId, results) => replaceTx(snapshotId, results),
    forSnapshot: (snapshotId) =>
      (sel.all(snapshotId) as { rule_id: string; resource_id: string; resource_type: string; status: RuleResult["status"] }[]).map(
        (r) => ({ ruleId: r.rule_id, resourceId: r.resource_id, resourceType: r.resource_type, status: r.status }),
      ),
  };
}

export function diffRepo(db: BetterSqlite3.Database): DiffRepo {
  const set = db.prepare(`
    INSERT INTO scan_diffs (snapshot_id, prev_snapshot_id, diff_json) VALUES (?, ?, ?)
    ON CONFLICT(snapshot_id) DO UPDATE SET prev_snapshot_id = excluded.prev_snapshot_id, diff_json = excluded.diff_json`);
  const get = db.prepare("SELECT diff_json FROM scan_diffs WHERE snapshot_id = ?");
  return {
    set: (snapshotId, diff) => {
      set.run(snapshotId, diff.prevSnapshotId, JSON.stringify(diff));
    },
    get: (snapshotId) => {
      const r = get.get(snapshotId) as { diff_json: string } | undefined;
      return r ? (JSON.parse(r.diff_json) as SnapshotDiff) : null;
    },
  };
}

// --- suppressions -----------------------------------------------------------

interface SuppressionRow {
  id: string;
  rule_id: string;
  resource_pattern: string;
  account_id: string | null;
  reason: string;
  created_by: string | null;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

function toSuppression(r: SuppressionRow): SuppressionRecord {
  return {
    id: r.id,
    ruleId: r.rule_id,
    resourcePattern: r.resource_pattern,
    accountId: r.account_id,
    reason: r.reason,
    createdBy: r.created_by,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    revokedAt: r.revoked_at,
  };
}

export function suppressionRepo(db: BetterSqlite3.Database, now: () => string): SuppressionRepo {
  const all = db.prepare("SELECT * FROM suppressions ORDER BY created_at DESC");
  const active = db.prepare(`
    SELECT * FROM suppressions WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
    ORDER BY created_at DESC`);
  const activeFor = db.prepare(`
    SELECT * FROM suppressions WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
      AND (account_id IS NULL OR account_id = ?) ORDER BY created_at DESC`);
  const get = db.prepare("SELECT * FROM suppressions WHERE id = ?");
  const ins = db.prepare(`
    INSERT INTO suppressions (id, rule_id, resource_pattern, account_id, reason, created_by, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  const revoke = db.prepare("UPDATE suppressions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL");
  return {
    list: (opts = {}) =>
      ((opts.includeInactive ? all.all() : active.all(now())) as SuppressionRow[]).map(toSuppression),
    get: (id) => {
      const r = get.get(id) as SuppressionRow | undefined;
      return r ? toSuppression(r) : null;
    },
    create: (input: NewSuppression) => {
      const id = randomUUID();
      ins.run(id, input.ruleId, input.resourcePattern, input.accountId ?? null, input.reason,
        input.createdBy ?? null, now(), input.expiresAt ?? null);
      return toSuppression(get.get(id) as SuppressionRow);
    },
    revoke: (id) => revoke.run(now(), id).changes > 0,
    activeFor: (accountId, at) => (activeFor.all(at, accountId) as SuppressionRow[]).map(toSuppression),
  };
}

// --- metadata ---------------------------------------------------------------

export function metadataRepo(db: BetterSqlite3.Database, now: () => string): MetadataRepo {
  const upsertRule = db.prepare(`
    INSERT INTO rules (id, version, title, severity, kind, resource_types_json, requires_json,
      controls_json, remediation_json, updated_at)
    VALUES (@id, @version, @title, @severity, @kind, @resource_types_json, @requires_json,
      @controls_json, @remediation_json, @updated_at)
    ON CONFLICT(id) DO UPDATE SET version = excluded.version, title = excluded.title,
      severity = excluded.severity, kind = excluded.kind,
      resource_types_json = excluded.resource_types_json, requires_json = excluded.requires_json,
      controls_json = excluded.controls_json, remediation_json = excluded.remediation_json,
      updated_at = excluded.updated_at`);
  const listRules = db.prepare("SELECT * FROM rules ORDER BY id");
  const delControls = db.prepare("DELETE FROM controls WHERE framework = ?");
  const insControl = db.prepare("INSERT INTO controls (framework, id, title, version) VALUES (?, ?, ?, ?)");
  const listControls = db.prepare("SELECT * FROM controls ORDER BY framework, id");
  const listControlsFor = db.prepare("SELECT * FROM controls WHERE framework = ? ORDER BY id");

  const syncRulesTx = db.transaction((rules: readonly RuleMeta[]) => {
    const ts = now();
    for (const r of rules) {
      upsertRule.run({
        id: r.id, version: r.version, title: r.title, severity: r.severity, kind: r.kind,
        resource_types_json: JSON.stringify(r.resourceTypes), requires_json: JSON.stringify(r.requires),
        controls_json: JSON.stringify(r.controls), remediation_json: JSON.stringify(r.remediation),
        updated_at: ts,
      });
    }
  });
  const syncControlsTx = db.transaction((framework: Framework, version: string, controls: readonly { id: string; title: string }[]) => {
    delControls.run(framework);
    for (const c of controls) insControl.run(framework, c.id, c.title, version);
  });

  interface RuleRow { id: string; version: number; title: string; severity: Severity; kind: string; resource_types_json: string; requires_json: string; controls_json: string; remediation_json: string }
  return {
    syncRules: (rules) => syncRulesTx(rules),
    listRules: () =>
      (listRules.all() as RuleRow[]).map((r) => ({
        id: r.id, version: r.version, title: r.title, severity: r.severity, kind: r.kind,
        resourceTypes: JSON.parse(r.resource_types_json) as string[],
        requires: JSON.parse(r.requires_json) as string[],
        controls: JSON.parse(r.controls_json) as RuleMeta["controls"],
        remediation: JSON.parse(r.remediation_json) as RuleMeta["remediation"],
      })),
    syncControls: (framework, version, controls) => syncControlsTx(framework, version, controls),
    listControls: (framework) =>
      ((framework ? listControlsFor.all(framework) : listControls.all()) as ControlRecord[]),
  };
}
