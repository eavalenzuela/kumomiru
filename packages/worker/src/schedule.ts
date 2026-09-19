import { Cron } from "croner";

/** Throws if `expr` is not a valid 5/6-field cron expression. */
export function assertValidCron(expr: string): void {
  new Cron(expr, { timezone: "UTC" });
}

/**
 * Whether a scan is due: the next cron occurrence strictly after the last
 * start is at or before `now`. Never scanned → due immediately.
 */
export function isDue(
  cronExpr: string,
  lastStartedAt: string | null,
  now: Date,
): boolean {
  if (!lastStartedAt) return true;
  const cron = new Cron(cronExpr, { timezone: "UTC" });
  const next = cron.nextRun(new Date(lastStartedAt));
  return next !== null && next.getTime() <= now.getTime();
}
