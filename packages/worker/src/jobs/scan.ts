import {
  CredentialBroker,
  DISCOVERY_CAPABILITIES,
  discoverGraph,
  mergeGraphs,
  stitchKnownAccounts,
  type AwsCredentials,
} from "@kumomiru/adapters";
import { checkReferentialIntegrity, diffSnapshots, type Graph } from "@kumomiru/graph";
import type { AccountRecord, Database, ScanRecord } from "@kumomiru/db";
import { defaultRegistry, evaluate } from "@kumomiru/rules";

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

    // Cross-account stitching: principals in other *registered* accounts are
    // siblings, not strangers (docs/cspm-roadmap.md Phase 5).
    const merged = stitchKnownAccounts(
      mergeGraphs(graphs, {
        generatedAt: deps.now().toISOString(),
        source: "aws-live",
        accountId: account.id,
        regions: covered,
      }),
      new Set(db.accounts.list().map((a) => a.id)),
    );
    const problems = checkReferentialIntegrity(merged);
    if (problems.length > 0) {
      db.scans.finish(scan.id, {
        status: "failed",
        error: `graph_integrity: ${problems.slice(0, 5).join("; ")}`,
      });
      log.error("scan failed: graph integrity", { scanId: scan.id, problems: problems.length });
      return;
    }

    // --- Rules, persistence, lifecycle, diff (Phase 2) -------------------
    // Rules run over the merged snapshot; their findings join the adapter
    // findings *in the stored graph* so the map shows them, and are then
    // reconciled against lifecycle state (open / reopened / resolved /
    // suppressed). The diff is against the previous stored snapshot.
    const registry = deps.registry ?? defaultRegistry();
    // The merged graph declares what its passes collected; that is what
    // decides `not-assessed`, not a static list.
    const evaluation = evaluate(merged, registry, {
      capabilities: deps.capabilities ?? merged.meta.capabilities ?? DISCOVERY_CAPABILITIES,
    });
    const graph: Graph = { ...merged, findings: evaluation.findings };
    const prevMeta = db.snapshots.latestForAccount(account.id);
    const prevGraph = prevMeta ? db.snapshots.getGraph(prevMeta.id) : null;

    const snapshot = db.snapshots.insert({ scanId: scan.id, accountId: account.id, graph });
    db.ruleResults.replaceForSnapshot(snapshot.id, evaluation.results);
    const observedAt = graph.meta.generatedAt;
    const lifecycle = db.findings.reconcile({
      accountId: account.id,
      snapshotId: snapshot.id,
      observedAt,
      findings: evaluation.findings,
      suppressions: db.suppressions.activeFor(account.id, observedAt),
    });
    const stored = db.snapshots.getGraph(snapshot.id) ?? graph;
    const diff = diffSnapshots(prevGraph, stored);
    db.diffs.set(snapshot.id, diff);

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
        nodes: graph.nodes.length,
        edges: graph.edges.length,
        findings: graph.findings.length,
        rulesNotAssessed: evaluation.notAssessedRules,
        feeds: merged.meta.feeds ?? [],
        securityHubControls: (merged.meta.securityHubControls ?? []).length,
        findingsSuperseded: evaluation.supersededFindings.length,
        findingsOpened: lifecycle.opened.length,
        findingsReopened: lifecycle.reopened.length,
        findingsResolved: lifecycle.resolved.length,
        findingsSuppressed: lifecycle.suppressed.length,
        nodesAdded: diff.nodesAdded.length,
        nodesRemoved: diff.nodesRemoved.length,
        nodesChanged: diff.nodesChanged.length,
        durationMs: deps.now().getTime() - started.getTime(),
      },
    });
    if (account.status !== "active") db.accounts.setStatus(account.id, "active");
    log.info("scan done", {
      scanId: scan.id,
      status: partial ? "partial" : "ok",
      snapshotId: snapshot.id,
      nodes: graph.nodes.length,
      findingsOpened: lifecycle.opened.length,
      findingsResolved: lifecycle.resolved.length,
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
