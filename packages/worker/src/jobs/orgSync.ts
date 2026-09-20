import { randomUUID } from "node:crypto";
import type { Database } from "@kumomiru/db";
import type { OrganizationsApi } from "@kumomiru/aws";

import type { Logger } from "../log.js";

/**
 * Organizations sync (docs/cspm-roadmap.md Phase 5). When enabled
 * (`org.sync.enabled` setting), list the member accounts with the worker's
 * host identity and register each as an `organizations`-onboarded account
 * pointing at `arn:aws:iam::<id>:role/<scanRoleName>` with the estate-wide
 * ExternalId. New accounts start `pending`; a verify scan is queued for
 * each pending one so they flip to `active` as soon as the StackSet lands.
 * Existing accounts keep their status and schedule. Never deletes.
 */
export const DEFAULT_SCAN_ROLE = "KumomiruScanRole";

export function ensureExternalId(db: Database): string {
  let id = db.settings.get<string>("org.externalId");
  if (!id) {
    id = `kumomiru-${randomUUID()}`;
    db.settings.set("org.externalId", id);
  }
  return id;
}

export async function runOrgSync(
  db: Database,
  input: { organizations: OrganizationsApi; region: string; partition?: string; now: () => Date },
  log: Logger,
): Promise<{ discovered: number; registered: number; verifyQueued: number } | null> {
  if (db.settings.get<boolean>("org.sync.enabled") !== true) return null;
  const roleName = db.settings.get<string>("org.scanRoleName") ?? DEFAULT_SCAN_ROLE;
  const externalId = ensureExternalId(db);
  const partition = input.partition ?? "aws";
  try {
    const listing = await input.organizations.listAccounts(input.region);
    let registered = 0;
    let verifyQueued = 0;
    for (const a of listing.accounts) {
      if (a.status !== "ACTIVE") continue;
      const before = db.accounts.get(a.id);
      db.accounts.upsert({
        id: a.id,
        name: before?.name ?? a.name,
        roleArn: before?.roleArn ?? `arn:${partition}:iam::${a.id}:role/${roleName}`,
        externalId: before?.externalId ?? externalId,
        onboarding: "organizations",
        orgId: listing.orgId,
        ouPath: a.ouPath,
        ...(a.email ? { email: a.email } : {}),
      });
      registered++;
      const after = db.accounts.get(a.id)!;
      if (after.status === "pending" && !db.scans.active(a.id)) {
        db.scans.enqueue(a.id, "verify");
        verifyQueued++;
      }
    }
    db.settings.set("org.sync.lastRun", input.now().toISOString());
    db.settings.set("org.sync.lastError", null);
    db.settings.set("org.sync.orgId", listing.orgId);
    log.info("org sync done", { orgId: listing.orgId, discovered: listing.accounts.length, registered, verifyQueued });
    return { discovered: listing.accounts.length, registered, verifyQueued };
  } catch (err) {
    const error = (err instanceof Error ? `${err.name}: ${err.message}` : String(err)).slice(0, 500);
    db.settings.set("org.sync.lastRun", input.now().toISOString());
    db.settings.set("org.sync.lastError", error);
    log.error("org sync failed", { error });
    return { discovered: 0, registered: 0, verifyQueued: 0 };
  }
}
