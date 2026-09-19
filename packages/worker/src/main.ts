import { hostname } from "node:os";
import { openDatabase } from "@kumomiru/db";
import { listEnabledRegions, makeSdkClient, sts } from "@kumomiru/aws";

import { consoleLogger } from "./log.js";
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
const scheduler = new Scheduler(
  db,
  {
    sts,
    listRegions: listEnabledRegions,
    makeClient: makeSdkClient,
    now: () => new Date(),
    workerId,
    stsRegion,
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
