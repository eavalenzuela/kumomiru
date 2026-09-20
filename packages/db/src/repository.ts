import type {
  ControlRef,
  Finding,
  FindingRecord,
  Framework,
  Graph,
  Remediation,
  RuleResult,
  Severity,
  SnapshotDiff,
} from "@kumomiru/graph";

/**
 * Record types and repository interfaces. Everything is synchronous because
 * the only implementation is embedded SQLite; a future Postgres implementation
 * would wrap these in an async facade at the call sites that need it.
 */

export type AccountStatus = "pending" | "active" | "inactive";
export type Onboarding = "manual" | "organizations";

export interface AccountRecord {
  /** 12-digit AWS account id. */
  id: string;
  name: string;
  /** The scan role the worker assumes in this account. */
  roleArn: string;
  externalId: string | null;
  /** Explicit region list, or null for "every enabled region". */
  regions: string[] | null;
  /** 5-field cron expression evaluated in UTC. */
  scheduleCron: string;
  onboarding: Onboarding;
  status: AccountStatus;
  /** From Organizations sync, when onboarded that way. */
  orgId: string | null;
  ouPath: string | null;
  email: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface NewAccount {
  id: string;
  name: string;
  roleArn: string;
  externalId?: string | null;
  regions?: string[] | null;
  scheduleCron?: string;
  onboarding?: Onboarding;
  status?: AccountStatus;
  orgId?: string | null;
  ouPath?: string | null;
  email?: string | null;
}

export type ScanStatus = "queued" | "running" | "ok" | "partial" | "failed";
export type ScanTrigger = "schedule" | "manual" | "verify";

export interface ScanRecord {
  id: string;
  accountId: string;
  status: ScanStatus;
  trigger: ScanTrigger;
  /** Regions the scan covered (filled in by the worker when it runs). */
  regions: string[];
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  /** Redacted, human-readable failure summary. Never raw SDK errors. */
  error: string | null;
  workerId: string | null;
  stats: Record<string, unknown> | null;
}

export interface SnapshotRecord {
  id: string;
  scanId: string;
  accountId: string;
  generatedAt: string;
  source: string;
  nodeCount: number;
  edgeCount: number;
  findingCount: number;
  prevSnapshotId: string | null;
  createdAt: string;
}

export interface AccountRepo {
  list(): AccountRecord[];
  get(id: string): AccountRecord | null;
  /** Insert or update by id. Status is preserved on update unless given. */
  upsert(account: NewAccount): AccountRecord;
  setStatus(id: string, status: AccountStatus): void;
  remove(id: string): boolean;
}

export interface ScanRepo {
  /** Queue a scan. Returns the existing active scan instead if one is queued/running. */
  enqueue(accountId: string, trigger: ScanTrigger): ScanRecord;
  get(id: string): ScanRecord | null;
  listForAccount(accountId: string, limit?: number): ScanRecord[];
  /** The queued or running scan for the account, if any. */
  active(accountId: string): ScanRecord | null;
  /**
   * Atomically take the oldest queued scan whose account has no running scan,
   * mark it running for `workerId`, and return it. Null when nothing to do.
   */
  claimNext(workerId: string): ScanRecord | null;
  /** Record the regions a running scan is covering. */
  setRegions(id: string, regions: string[]): void;
  finish(
    id: string,
    result: {
      status: Extract<ScanStatus, "ok" | "partial" | "failed">;
      error?: string | null;
      stats?: Record<string, unknown> | null;
    },
  ): void;
  /** Start time of the most recent scan for the account (any status). */
  lastStartedAt(accountId: string): string | null;
}

export interface SnapshotRepo {
  insert(input: { scanId: string; accountId: string; graph: Graph }): SnapshotRecord;
  get(id: string): SnapshotRecord | null;
  /** The stored graph, with meta.snapshotId / scanId filled in. */
  getGraph(id: string): Graph | null;
  latestForAccount(accountId: string): SnapshotRecord | null;
  listForAccount(accountId: string, limit?: number): SnapshotRecord[];
}

export interface SettingsRepo {
  get<T = unknown>(key: string): T | null;
  set(key: string, value: unknown): void;
}

export interface LeaseRepo {
  /**
   * Take or renew a named lease for `holder`. Returns false if another holder
   * owns it and it has not expired. Used so only one worker runs the
   * scheduler tick at a time.
   */
  acquire(name: string, holder: string, ttlMs: number): boolean;
  release(name: string, holder: string): void;
}

// --- lifecycle (Phase 2) ----------------------------------------------------

export interface SuppressionRecord {
  id: string;
  ruleId: string;
  /** Exact resource id, `*`, or a glob with `*` wildcards. */
  resourcePattern: string;
  accountId: string | null;
  reason: string;
  createdBy: string | null;
  createdAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

export interface NewSuppression {
  ruleId: string;
  resourcePattern: string;
  accountId?: string | null;
  reason: string;
  createdBy?: string | null;
  expiresAt?: string | null;
}

export interface ReconcileSummary {
  opened: string[];
  reopened: string[];
  resolved: string[];
  suppressed: string[];
  unchanged: number;
}

export interface FindingFilter {
  accountId?: string;
  status?: FindingRecord["status"];
  severity?: Severity;
  ruleId?: string;
  source?: FindingRecord["source"];
  control?: ControlRef;
  limit?: number;
}

export interface FindingRepo {
  /**
   * Bring stored lifecycle state in line with what a snapshot observed:
   * unseen ids open (or start suppressed if a suppression matches), previously
   * resolved ids reopen, seen ids refresh, and open/suppressed ids not observed
   * resolve. Atomic.
   */
  reconcile(input: {
    accountId: string;
    snapshotId: string;
    observedAt: string;
    findings: readonly Finding[];
    suppressions: readonly SuppressionRecord[];
  }): ReconcileSummary;
  list(filter?: FindingFilter): FindingRecord[];
  get(id: string): FindingRecord | null;
  /** Open findings by severity for one account, or all accounts. */
  openCounts(accountId?: string): Record<Severity, number>;
  /** Re-evaluate suppression on open/suppressed findings after a change. */
  applySuppressions(suppressions: readonly SuppressionRecord[], now: string): void;
}

export interface RuleResultRepo {
  replaceForSnapshot(snapshotId: string, results: readonly RuleResult[]): void;
  forSnapshot(snapshotId: string): RuleResult[];
}

export interface DiffRepo {
  set(snapshotId: string, diff: SnapshotDiff): void;
  get(snapshotId: string): SnapshotDiff | null;
}

export interface SuppressionRepo {
  list(opts?: { includeInactive?: boolean }): SuppressionRecord[];
  get(id: string): SuppressionRecord | null;
  create(input: NewSuppression): SuppressionRecord;
  revoke(id: string): boolean;
  /** Suppressions in force for an account at `now` (global ones included). */
  activeFor(accountId: string, now: string): SuppressionRecord[];
}

export interface RuleMeta {
  id: string;
  version: number;
  title: string;
  severity: Severity;
  kind: string;
  resourceTypes: string[];
  requires: string[];
  controls: ControlRef[];
  remediation: Remediation;
}

export interface ControlRecord {
  framework: Framework;
  id: string;
  title: string;
  version: string;
}

export interface MetadataRepo {
  syncRules(rules: readonly RuleMeta[]): void;
  listRules(): RuleMeta[];
  syncControls(framework: Framework, version: string, controls: readonly { id: string; title: string }[]): void;
  listControls(framework?: Framework): ControlRecord[];
}

export type UserRole = "viewer" | "admin";

export interface UserRecord {
  id: string;
  email: string;
  name: string | null;
  idpSubject: string;
  idpIssuer: string;
  role: UserRole;
  createdAt: string;
  lastLoginAt: string | null;
  disabled: boolean;
}

export interface UserRepo {
  list(): UserRecord[];
  get(id: string): UserRecord | null;
  getByEmail(email: string): UserRecord | null;
  /** Upsert on login by (issuer, subject); email/name refreshed; role kept unless given. */
  upsertOnLogin(input: { email: string; name?: string | null; idpSubject: string; idpIssuer: string; role?: UserRole }): UserRecord;
  setRole(id: string, role: UserRole): boolean;
  setDisabled(id: string, disabled: boolean): boolean;
  count(): number;
}

export interface Database {
  users: UserRepo;
  accounts: AccountRepo;
  scans: ScanRepo;
  snapshots: SnapshotRepo;
  settings: SettingsRepo;
  leases: LeaseRepo;
  findings: FindingRepo;
  ruleResults: RuleResultRepo;
  diffs: DiffRepo;
  suppressions: SuppressionRepo;
  metadata: MetadataRepo;
  close(): void;
}
