import { hostname } from "node:os";
import { openDatabase } from "@kumomiru/db";
import { listEnabledRegions, makeSdkClient, organizations, sts } from "@kumomiru/aws";

import { defaultRegistry } from "@kumomiru/rules";

import { consoleLogger } from "./log.js";
import { syncRuleMetadata } from "./metadata.js";
import { Scheduler } from "./scheduler.js";

/**
 * Worker entry point. Reads its config from the environment, opens the shared
 * SQLite file, and runs the scheduler until SIGTERM/SIGINT.
 */
const env = process.env;
const dbPath = env["KUMOMIRU_DB_PATH"] ?? "./kumomiru.db";
const workerId = env["KUMOMIRU_WORKER_ID"] ?? `${hostname()}-${process.pid}`;
const pollMs = Number(env["KUMOMIRU_POLL_SECONDS"] ?? 30) * 1000;
const stsRegion = env["KUMOMIRU_STS_REGION"] ?? "us-east-1";

const db = openDatabase(dbPath);
const registry = defaultRegistry();
syncRuleMetadata(db, registry);

// Record who we are so the server can render the scan-role trust policy and
// StackSet. Best effort: a worker with no AWS identity still serves as a
// scheduler for accounts that are already active.
try {
  const id = await sts.hostIdentity(stsRegion);
  db.settings.set("worker.hostIdentity", { ...id, recordedAt: new Date().toISOString() });
  consoleLogger.info("worker host identity", id);
} catch (err) {
  consoleLogger.warn("could not resolve host identity", { error: err instanceof Error ? err.message : String(err) });
}
const scheduler = new Scheduler(
  db,
  {
    sts,
    listRegions: listEnabledRegions,
    makeClient: makeSdkClient,
    now: () => new Date(),
    workerId,
    stsRegion,
    registry,
    organizations,
  },
  { pollMs, log: consoleLogger },
);

consoleLogger.info("worker starting", { workerId, dbPath, pollMs });
scheduler.start();

const shutdown = () => {
  consoleLogger.info("worker stopping", { workerId });
  scheduler.stop();
  db.close();
  process.exit(0);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
