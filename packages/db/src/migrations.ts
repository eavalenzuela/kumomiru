/**
 * Numbered migrations applied in order on open; `PRAGMA user_version` records
 * the last one applied. Append only — never edit an applied migration.
 */
export const MIGRATIONS: readonly string[] = [
  // 0001_init
  `
  CREATE TABLE accounts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    role_arn      TEXT NOT NULL,
    external_id   TEXT,
    regions_json  TEXT,
    schedule_cron TEXT NOT NULL,
    onboarding    TEXT NOT NULL CHECK (onboarding IN ('manual','organizations')),
    status        TEXT NOT NULL CHECK (status IN ('pending','active','inactive')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
  );

  CREATE TABLE scans (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    status       TEXT NOT NULL CHECK (status IN ('queued','running','ok','partial','failed')),
    trigger      TEXT NOT NULL CHECK (trigger IN ('schedule','manual','verify')),
    regions_json TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    error        TEXT,
    worker_id    TEXT,
    stats_json   TEXT
  );
  CREATE INDEX scans_account_created ON scans(account_id, created_at DESC);
  CREATE INDEX scans_status ON scans(status);

  CREATE TABLE snapshots (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    account_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    generated_at     TEXT NOT NULL,
    source           TEXT NOT NULL,
    graph_json       TEXT NOT NULL,
    node_count       INTEGER NOT NULL,
    edge_count       INTEGER NOT NULL,
    finding_count    INTEGER NOT NULL,
    prev_snapshot_id TEXT,
    created_at       TEXT NOT NULL
  );
  CREATE INDEX snapshots_account_generated ON snapshots(account_id, generated_at DESC);

  CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
  );

  CREATE TABLE worker_leases (
    name       TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  `,
];
