import { randomUUID } from "node:crypto";
import BetterSqlite3 from "better-sqlite3";
import type { Graph } from "@kumomiru/graph";

import { MIGRATIONS } from "./migrations.js";
import type {
  AccountRecord,
  AccountRepo,
  AccountStatus,
  Database,
  LeaseRepo,
  NewAccount,
  ScanRecord,
  ScanRepo,
  ScanTrigger,
  SettingsRepo,
  SnapshotRecord,
  SnapshotRepo,
} from "./repository.js";

export interface OpenOptions {
  /** Clock, injectable for deterministic tests. */
  now?: () => Date;
}

const DEFAULT_SCHEDULE = "0 */6 * * *";

/**
 * Open (or create) the SQLite database at `path` and apply pending migrations.
 * `":memory:"` gives an isolated throwaway database for tests.
 *
 * WAL mode + a busy timeout let the worker and the API server share one file:
 * readers never block the writer and short write contention waits instead of
 * failing.
 */
export function openDatabase(path: string, opts: OpenOptions = {}): Database {
  const db = new BetterSqlite3(path);
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.pragma("foreign_keys = ON");
  migrate(db);

  const now = () => (opts.now?.() ?? new Date()).toISOString();
  const nowMs = () => (opts.now?.() ?? new Date()).getTime();

  return {
    accounts: accountRepo(db, now),
    scans: scanRepo(db, now),
    snapshots: snapshotRepo(db, now),
    settings: settingsRepo(db),
    leases: leaseRepo(db, nowMs),
    close: () => db.close(),
  };
}

function migrate(db: BetterSqlite3.Database): void {
  const current = db.pragma("user_version", { simple: true }) as number;
  for (let i = current; i < MIGRATIONS.length; i++) {
    db.transaction(() => {
      db.exec(MIGRATIONS[i]!);
      db.pragma(`user_version = ${i + 1}`);
    })();
  }
}

// --- accounts ---------------------------------------------------------------

interface AccountRow {
  id: string;
  name: string;
  role_arn: string;
  external_id: string | null;
  regions_json: string | null;
  schedule_cron: string;
  onboarding: string;
  status: string;
  created_at: string;
  updated_at: string;
}

function toAccount(r: AccountRow): AccountRecord {
  return {
    id: r.id,
    name: r.name,
    roleArn: r.role_arn,
    externalId: r.external_id,
    regions: r.regions_json ? (JSON.parse(r.regions_json) as string[]) : null,
    scheduleCron: r.schedule_cron,
    onboarding: r.onboarding as AccountRecord["onboarding"],
    status: r.status as AccountStatus,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function accountRepo(db: BetterSqlite3.Database, now: () => string): AccountRepo {
  const list = db.prepare("SELECT * FROM accounts ORDER BY id");
  const get = db.prepare("SELECT * FROM accounts WHERE id = ?");
  const insert = db.prepare(`
    INSERT INTO accounts (id, name, role_arn, external_id, regions_json,
      schedule_cron, onboarding, status, created_at, updated_at)
    VALUES (@id, @name, @role_arn, @external_id, @regions_json,
      @schedule_cron, @onboarding, @status, @created_at, @updated_at)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      role_arn = excluded.role_arn,
      external_id = excluded.external_id,
      regions_json = excluded.regions_json,
      schedule_cron = excluded.schedule_cron,
      onboarding = excluded.onboarding,
      status = COALESCE(@status_override, accounts.status),
      updated_at = excluded.updated_at
  `);
  const setStatus = db.prepare(
    "UPDATE accounts SET status = ?, updated_at = ? WHERE id = ?",
  );
  const remove = db.prepare("DELETE FROM accounts WHERE id = ?");
  return {
    list: () => (list.all() as AccountRow[]).map(toAccount),
    get: (id) => {
      const r = get.get(id) as AccountRow | undefined;
      return r ? toAccount(r) : null;
    },
    upsert: (a) => {
      const ts = now();
      insert.run({
        id: a.id,
        name: a.name,
        role_arn: a.roleArn,
        external_id: a.externalId ?? null,
        regions_json: a.regions ? JSON.stringify(a.regions) : null,
        schedule_cron: a.scheduleCron ?? DEFAULT_SCHEDULE,
        onboarding: a.onboarding ?? "manual",
        status: a.status ?? "pending",
        status_override: a.status ?? null,
        created_at: ts,
        updated_at: ts,
      });
      return toAccount(get.get(a.id) as AccountRow);
    },
    setStatus: (id, status) => {
      setStatus.run(status, now(), id);
    },
    remove: (id) => remove.run(id).changes > 0,
  };
}

// --- scans ------------------------------------------------------------------

interface ScanRow {
  id: string;
  account_id: string;
  status: string;
  trigger: string;
  regions_json: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  worker_id: string | null;
  stats_json: string | null;
}

function toScan(r: ScanRow): ScanRecord {
  return {
    id: r.id,
    accountId: r.account_id,
    status: r.status as ScanRecord["status"],
    trigger: r.trigger as ScanTrigger,
    regions: JSON.parse(r.regions_json) as string[],
    createdAt: r.created_at,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    error: r.error,
    workerId: r.worker_id,
    stats: r.stats_json ? (JSON.parse(r.stats_json) as Record<string, unknown>) : null,
  };
}

function scanRepo(db: BetterSqlite3.Database, now: () => string): ScanRepo {
  const get = db.prepare("SELECT * FROM scans WHERE id = ?");
  const active = db.prepare(`
    SELECT * FROM scans WHERE account_id = ? AND status IN ('queued','running')
    ORDER BY created_at LIMIT 1`);
  const insert = db.prepare(`
    INSERT INTO scans (id, account_id, status, trigger, created_at)
    VALUES (?, ?, 'queued', ?, ?)`);
  const listFor = db.prepare(
    "SELECT * FROM scans WHERE account_id = ? ORDER BY created_at DESC LIMIT ?",
  );
  const nextQueued = db.prepare(`
    SELECT s.* FROM scans s
    WHERE s.status = 'queued'
      AND NOT EXISTS (
        SELECT 1 FROM scans r WHERE r.account_id = s.account_id AND r.status = 'running')
    ORDER BY s.created_at LIMIT 1`);
  const claim = db.prepare(`
    UPDATE scans SET status = 'running', started_at = ?, worker_id = ?
    WHERE id = ? AND status = 'queued'`);
  const setRegions = db.prepare("UPDATE scans SET regions_json = ? WHERE id = ?");
  const finish = db.prepare(`
    UPDATE scans SET status = ?, finished_at = ?, error = ?, stats_json = ?
    WHERE id = ?`);
  const last = db.prepare(`
    SELECT started_at FROM scans WHERE account_id = ? AND started_at IS NOT NULL
    ORDER BY started_at DESC LIMIT 1`);

  const claimTx = db.transaction((workerId: string): ScanRecord | null => {
    const r = nextQueued.get() as ScanRow | undefined;
    if (!r) return null;
    const res = claim.run(now(), workerId, r.id);
    if (res.changes !== 1) return null;
    return toScan(get.get(r.id) as ScanRow);
  });

  return {
    enqueue: (accountId, trigger) => {
      const existing = active.get(accountId) as ScanRow | undefined;
      if (existing) return toScan(existing);
      const id = randomUUID();
      insert.run(id, accountId, trigger, now());
      return toScan(get.get(id) as ScanRow);
    },
    get: (id) => {
      const r = get.get(id) as ScanRow | undefined;
      return r ? toScan(r) : null;
    },
    listForAccount: (accountId, limit = 50) =>
      (listFor.all(accountId, limit) as ScanRow[]).map(toScan),
    active: (accountId) => {
      const r = active.get(accountId) as ScanRow | undefined;
      return r ? toScan(r) : null;
    },
    claimNext: (workerId) => claimTx(workerId),
    setRegions: (id, regions) => {
      setRegions.run(JSON.stringify(regions), id);
    },
    finish: (id, result) => {
      finish.run(
        result.status,
        now(),
        result.error ?? null,
        result.stats ? JSON.stringify(result.stats) : null,
        id,
      );
    },
    lastStartedAt: (accountId) => {
      const r = last.get(accountId) as { started_at: string } | undefined;
      return r?.started_at ?? null;
    },
  };
}

// --- snapshots --------------------------------------------------------------

interface SnapshotRow {
  id: string;
  scan_id: string;
  account_id: string;
  generated_at: string;
  source: string;
  node_count: number;
  edge_count: number;
  finding_count: number;
  prev_snapshot_id: string | null;
  created_at: string;
}

function toSnapshot(r: SnapshotRow): SnapshotRecord {
  return {
    id: r.id,
    scanId: r.scan_id,
    accountId: r.account_id,
    generatedAt: r.generated_at,
    source: r.source,
    nodeCount: r.node_count,
    edgeCount: r.edge_count,
    findingCount: r.finding_count,
    prevSnapshotId: r.prev_snapshot_id,
    createdAt: r.created_at,
  };
}

const SNAPSHOT_COLS = `id, scan_id, account_id, generated_at, source, node_count,
  edge_count, finding_count, prev_snapshot_id, created_at`;

function snapshotRepo(db: BetterSqlite3.Database, now: () => string): SnapshotRepo {
  const get = db.prepare(`SELECT ${SNAPSHOT_COLS} FROM snapshots WHERE id = ?`);
  const getGraph = db.prepare("SELECT graph_json FROM snapshots WHERE id = ?");
  const latest = db.prepare(`
    SELECT ${SNAPSHOT_COLS} FROM snapshots WHERE account_id = ?
    ORDER BY generated_at DESC LIMIT 1`);
  const listFor = db.prepare(`
    SELECT ${SNAPSHOT_COLS} FROM snapshots WHERE account_id = ?
    ORDER BY generated_at DESC LIMIT ?`);
  const insert = db.prepare(`
    INSERT INTO snapshots (id, scan_id, account_id, generated_at, source, graph_json,
      node_count, edge_count, finding_count, prev_snapshot_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

  const insertTx = db.transaction(
    (input: { scanId: string; accountId: string; graph: Graph }): SnapshotRecord => {
      const prev = latest.get(input.accountId) as SnapshotRow | undefined;
      const id = randomUUID();
      const graph: Graph = {
        ...input.graph,
        meta: { ...input.graph.meta, snapshotId: id, scanId: input.scanId },
      };
      insert.run(
        id,
        input.scanId,
        input.accountId,
        graph.meta.generatedAt,
        graph.meta.source,
        JSON.stringify(graph),
        graph.nodes.length,
        graph.edges.length,
        graph.findings.length,
        prev?.id ?? null,
        now(),
      );
      return toSnapshot(get.get(id) as SnapshotRow);
    },
  );

  return {
    insert: (input) => insertTx(input),
    get: (id) => {
      const r = get.get(id) as SnapshotRow | undefined;
      return r ? toSnapshot(r) : null;
    },
    getGraph: (id) => {
      const r = getGraph.get(id) as { graph_json: string } | undefined;
      return r ? (JSON.parse(r.graph_json) as Graph) : null;
    },
    latestForAccount: (accountId) => {
      const r = latest.get(accountId) as SnapshotRow | undefined;
      return r ? toSnapshot(r) : null;
    },
    listForAccount: (accountId, limit = 50) =>
      (listFor.all(accountId, limit) as SnapshotRow[]).map(toSnapshot),
  };
}

// --- settings / leases ------------------------------------------------------

function settingsRepo(db: BetterSqlite3.Database): SettingsRepo {
  const get = db.prepare("SELECT value_json FROM settings WHERE key = ?");
  const set = db.prepare(`
    INSERT INTO settings (key, value_json) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json`);
  return {
    get: <T>(key: string): T | null => {
      const r = get.get(key) as { value_json: string } | undefined;
      return r ? (JSON.parse(r.value_json) as T) : null;
    },
    set: (key, value) => {
      set.run(key, JSON.stringify(value));
    },
  };
}

function leaseRepo(db: BetterSqlite3.Database, nowMs: () => number): LeaseRepo {
  const get = db.prepare("SELECT holder, expires_at FROM worker_leases WHERE name = ?");
  const upsert = db.prepare(`
    INSERT INTO worker_leases (name, holder, expires_at) VALUES (?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at`);
  const release = db.prepare(
    "DELETE FROM worker_leases WHERE name = ? AND holder = ?",
  );
  const acquireTx = db.transaction((name: string, holder: string, ttlMs: number) => {
    const t = nowMs();
    const cur = get.get(name) as { holder: string; expires_at: number } | undefined;
    if (cur && cur.holder !== holder && cur.expires_at > t) return false;
    upsert.run(name, holder, t + ttlMs);
    return true;
  });
  return {
    acquire: (name, holder, ttlMs) => acquireTx(name, holder, ttlMs) as boolean,
    release: (name, holder) => {
      release.run(name, holder);
    },
  };
}
