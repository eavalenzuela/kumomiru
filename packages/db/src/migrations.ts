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
  // 0002_lifecycle — findings with lifecycle, rule results, diffs, suppressions, metadata
  `
  CREATE TABLE findings (
    id               TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    rule_id          TEXT,
    source           TEXT NOT NULL DEFAULT 'native',
    severity         TEXT NOT NULL,
    kind             TEXT NOT NULL,
    resource_id      TEXT,
    resource_type    TEXT,
    title            TEXT NOT NULL,
    detail           TEXT NOT NULL,
    controls_json    TEXT NOT NULL DEFAULT '[]',
    remediation_json TEXT,
    evidence_json    TEXT,
    external_id      TEXT,
    status           TEXT NOT NULL CHECK (status IN ('open','resolved','suppressed')),
    first_seen_at    TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL,
    resolved_at      TEXT,
    last_snapshot_id TEXT NOT NULL,
    suppression_id   TEXT
  );
  CREATE INDEX findings_account_status_sev ON findings(account_id, status, severity);
  CREATE INDEX findings_rule ON findings(rule_id);

  CREATE TABLE rule_results (
    snapshot_id   TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pass','fail','not-applicable','not-assessed')),
    PRIMARY KEY (snapshot_id, rule_id, resource_id)
  );
  CREATE INDEX rule_results_rule_status ON rule_results(rule_id, status);

  CREATE TABLE scan_diffs (
    snapshot_id      TEXT PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
    prev_snapshot_id TEXT,
    diff_json        TEXT NOT NULL
  );

  CREATE TABLE suppressions (
    id               TEXT PRIMARY KEY,
    rule_id          TEXT NOT NULL,
    resource_pattern TEXT NOT NULL,
    account_id       TEXT,
    reason           TEXT NOT NULL,
    created_by       TEXT,
    created_at       TEXT NOT NULL,
    expires_at       TEXT,
    revoked_at       TEXT
  );

  CREATE TABLE rules (
    id                  TEXT PRIMARY KEY,
    version             INTEGER NOT NULL,
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL,
    kind                TEXT NOT NULL,
    resource_types_json TEXT NOT NULL,
    requires_json       TEXT NOT NULL,
    controls_json       TEXT NOT NULL,
    remediation_json    TEXT NOT NULL,
    updated_at          TEXT NOT NULL
  );

  CREATE TABLE controls (
    framework   TEXT NOT NULL,
    id          TEXT NOT NULL,
    title       TEXT NOT NULL,
    version     TEXT NOT NULL,
    PRIMARY KEY (framework, id)
  );
  `,
  // 0003_auth_org — users (OIDC), organization columns on accounts
  `
  CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT,
    idp_subject   TEXT NOT NULL,
    idp_issuer    TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('viewer','admin')),
    created_at    TEXT NOT NULL,
    last_login_at TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0
  );
  ALTER TABLE accounts ADD COLUMN org_id TEXT;
  ALTER TABLE accounts ADD COLUMN ou_path TEXT;
  ALTER TABLE accounts ADD COLUMN email TEXT;
  `,
];
