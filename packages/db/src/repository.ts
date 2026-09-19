import type { Graph } from "@kumomiru/graph";

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

export interface Database {
  accounts: AccountRepo;
  scans: ScanRepo;
  snapshots: SnapshotRepo;
  settings: SettingsRepo;
  leases: LeaseRepo;
  close(): void;
}
