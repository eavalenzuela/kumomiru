import {
  CredentialBroker,
  discoverGraph,
  mergeGraphs,
  type AwsCredentials,
} from "@kumomiru/adapters";
import { checkReferentialIntegrity, type Graph } from "@kumomiru/graph";
import type { AccountRecord, Database, ScanRecord } from "@kumomiru/db";

import type { WorkerDeps } from "../deps.js";
import type { Logger } from "../log.js";

/** Keep failure text short and free of anything an SDK error might carry. */
function summarize(err: unknown): string {
  const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
  return msg.slice(0, 500);
}

/** Overwrite the secret fields of a credential object we own. */
function scrub(creds: AwsCredentials): void {
  creds.accessKeyId = "";
  creds.secretAccessKey = "";
  creds.sessionToken = "";
}

/**
 * Run one claimed scan to completion and record the outcome. Never throws:
 * every failure path ends in `scans.finish`.
 *
 * Credential lifecycle: the role is assumed once; each discovery pass borrows a
 * *copy* of the temporary credentials through a `CredentialBroker`, which
 * scrubs its copy afterwards. The master copy is scrubbed in `finally`.
 */
export async function runScan(
  scan: ScanRecord,
  account: AccountRecord,
  db: Database,
  deps: WorkerDeps,
  log: Logger,
): Promise<void> {
  const started = deps.now();
  log.info("scan start", { scanId: scan.id, accountId: account.id, trigger: scan.trigger });

  let master: AwsCredentials | null = null;
  try {
    master = await deps.sts.assumeRole({
      roleArn: account.roleArn,
      ...(account.externalId ? { externalId: account.externalId } : {}),
      region: deps.stsRegion,
      sessionName: `kumomiru-${scan.id.slice(0, 8)}`,
    });

    if (scan.trigger === "verify") {
      await verify(scan, account, db, deps, master);
      return;
    }

    const regions = account.regions ?? (await deps.listRegions(master));
    db.scans.setRegions(scan.id, regions);

    // One global pass (IAM), then one regional pass per region. A regional
    // failure is recorded and skipped; the scan still yields a snapshot.
    const global = await pass(master, deps, { scope: "global", region: deps.stsRegion });
    const graphs: Graph[] = [global];
    const failed: Record<string, string> = {};
    for (const region of regions) {
      try {
        graphs.push(await pass(master, deps, { scope: "regional", region }));
      } catch (err) {
        failed[region] = summarize(err);
        log.warn("region failed", { scanId: scan.id, region, error: failed[region] });
      }
    }
    const covered = regions.filter((r) => !(r in failed));

    const merged = mergeGraphs(graphs, {
      generatedAt: deps.now().toISOString(),
      source: "aws-live",
      accountId: account.id,
      regions: covered,
    });
    const problems = checkReferentialIntegrity(merged);
    if (problems.length > 0) {
      db.scans.finish(scan.id, {
        status: "failed",
        error: `graph_integrity: ${problems.slice(0, 5).join("; ")}`,
      });
      log.error("scan failed: graph integrity", { scanId: scan.id, problems: problems.length });
      return;
    }

    const snapshot = db.snapshots.insert({ scanId: scan.id, accountId: account.id, graph: merged });
    const partial = Object.keys(failed).length > 0;
    db.scans.finish(scan.id, {
      status: partial ? "partial" : "ok",
      error: partial
        ? Object.entries(failed).map(([r, e]) => `${r}: ${e}`).join(" | ")
        : null,
      stats: {
        snapshotId: snapshot.id,
        regions: covered,
        failedRegions: Object.keys(failed),
        nodes: merged.nodes.length,
        edges: merged.edges.length,
        findings: merged.findings.length,
        durationMs: deps.now().getTime() - started.getTime(),
      },
    });
    if (account.status !== "active") db.accounts.setStatus(account.id, "active");
    log.info("scan done", {
      scanId: scan.id,
      status: partial ? "partial" : "ok",
      snapshotId: snapshot.id,
      nodes: merged.nodes.length,
    });
  } catch (err) {
    const error = summarize(err);
    db.scans.finish(scan.id, { status: "failed", error });
    log.error("scan failed", { scanId: scan.id, error });
  } finally {
    if (master) scrub(master);
  }
}

/** Borrow a copy of the credentials for exactly one discovery pass. */
async function pass(
  master: AwsCredentials,
  deps: WorkerDeps,
  opts: { scope: "global" | "regional"; region: string },
): Promise<Graph> {
  const broker = new CredentialBroker({ ...master, region: opts.region });
  return broker.use(async (borrowed) => {
    const client = await deps.makeClient(borrowed);
    return discoverGraph(client, { scope: opts.scope, now: deps.now });
  });
}

/**
 * `verify` trigger: prove the role can be assumed and that it lands in the
 * registered account, then mark the account active. No discovery.
 */
async function verify(
  scan: ScanRecord,
  account: AccountRecord,
  db: Database,
  deps: WorkerDeps,
  master: AwsCredentials,
): Promise<void> {
  const broker = new CredentialBroker({ ...master });
  const seen = await broker.use(async (borrowed) => {
    const client = await deps.makeClient(borrowed);
    return client.accountId();
  });
  if (seen !== account.id) {
    db.scans.finish(scan.id, {
      status: "failed",
      error: `role ${account.roleArn} resolved to account ${seen}, expected ${account.id}`,
    });
    return;
  }
  db.accounts.setStatus(account.id, "active");
  db.scans.finish(scan.id, { status: "ok", stats: { verified: true } });
}
