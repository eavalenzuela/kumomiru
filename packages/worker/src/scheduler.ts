import type { Database } from "@kumomiru/db";

import type { WorkerDeps } from "./deps.js";
import { runScan } from "./jobs/scan.js";
import type { Logger } from "./log.js";
import { isDue } from "./schedule.js";

export interface SchedulerOptions {
  pollMs?: number;
  leaseTtlMs?: number;
  log?: Logger;
}

const LEASE = "scheduler";

/**
 * The worker loop. One `tick` does two independent things:
 *
 * 1. If this worker holds the scheduler lease, enqueue a scan for every active
 *    account whose schedule is due. The lease means several workers can run
 *    without double-enqueueing; `ScanRepo.enqueue` is idempotent anyway.
 * 2. Claim and run queued scans until none are claimable. `claimNext` is
 *    atomic and skips accounts that already have a running scan, so two
 *    workers never scan the same account at once.
 */
export class Scheduler {
  readonly #db: Database;
  readonly #deps: WorkerDeps;
  readonly #pollMs: number;
  readonly #leaseTtlMs: number;
  readonly #log: Logger;
  #timer: NodeJS.Timeout | null = null;
  #running = false;

  constructor(db: Database, deps: WorkerDeps, opts: SchedulerOptions = {}) {
    this.#db = db;
    this.#deps = deps;
    this.#pollMs = opts.pollMs ?? 30_000;
    this.#leaseTtlMs = opts.leaseTtlMs ?? this.#pollMs * 3;
    this.#log = opts.log ?? { info() {}, warn() {}, error() {} };
  }

  /** Enqueue due scans (if lease held) and drain the queue. Safe to call directly in tests. */
  async tick(): Promise<{ enqueued: number; ran: number }> {
    let enqueued = 0;
    if (this.#db.leases.acquire(LEASE, this.#deps.workerId, this.#leaseTtlMs)) {
      const now = this.#deps.now();
      for (const account of this.#db.accounts.list()) {
        if (account.status !== "active") continue;
        if (this.#db.scans.active(account.id)) continue;
        if (!isDue(account.scheduleCron, this.#db.scans.lastStartedAt(account.id), now)) continue;
        this.#db.scans.enqueue(account.id, "schedule");
        enqueued++;
      }
    }

    let ran = 0;
    for (;;) {
      const scan = this.#db.scans.claimNext(this.#deps.workerId);
      if (!scan) break;
      const account = this.#db.accounts.get(scan.accountId);
      if (!account) {
        this.#db.scans.finish(scan.id, { status: "failed", error: "account no longer exists" });
        continue;
      }
      await runScan(scan, account, this.#db, this.#deps, this.#log);
      ran++;
    }
    return { enqueued, ran };
  }

  start(): void {
    if (this.#timer) return;
    const loop = async () => {
      if (this.#running) return;
      this.#running = true;
      try {
        await this.tick();
      } catch (err) {
        this.#log.error("tick failed", { error: err instanceof Error ? err.message : String(err) });
      } finally {
        this.#running = false;
      }
    };
    void loop();
    this.#timer = setInterval(() => void loop(), this.#pollMs);
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    this.#db.leases.release(LEASE, this.#deps.workerId);
  }
}
