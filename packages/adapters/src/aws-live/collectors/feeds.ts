import type { CloudEdge, Finding } from "@kumomiru/graph";
import { mapAsffFindings } from "../../feeds/asff.js";
import { mapAccessAnalyzerFindings } from "../../feeds/accessanalyzer.js";
import type { CollectContext } from "../collect.js";

export interface FeedOutcome {
  feeds: string[];
  securityHubControls: string[];
}

/**
 * Managed feeds, run after collection and the native IAM passes so their
 * output can be matched to nodes and supersede native findings:
 *
 * - Security Hub findings join `ctx.findings` as `source: "securityhub"`;
 *   the controls it reported on are returned for `meta.securityHubControls`.
 * - Access Analyzer findings replace native `public-resource` /
 *   `external-can-access` findings for every resource they cover, and add
 *   their own `can-access` edges (deduped against native ones by target).
 */
export async function collectFeeds(ctx: CollectContext): Promise<FeedOutcome> {
  const { client, nodes, edges, findings, accountNode } = ctx;
  const feeds: string[] = [];
  let securityHubControls: string[] = [];
  const known = new Set(nodes.map((n) => n.id));

  if (client.securityHubFindings) {
    const sh = await client.securityHubFindings();
    if (sh.enabled) {
      feeds.push("securityhub");
      const mapped = mapAsffFindings(sh.findings, known);
      findings.push(...mapped.findings);
      securityHubControls = mapped.coveredControls;
    }
  }

  if (client.accessAnalyzerFindings) {
    const aa = await client.accessAnalyzerFindings();
    if (aa.enabled) {
      feeds.push("accessanalyzer");
      const mapped = mapAccessAnalyzerFindings(aa.findings, known, accountNode);
      const covered = new Set(mapped.coveredResources);
      // Native resource-policy findings for covered resources are superseded.
      const keep: Finding[] = [];
      for (const f of findings) {
        const native = (f.kind === "public-resource" || f.kind === "external-can-access") && f.source !== "accessanalyzer";
        if (native && f.nodeId && covered.has(f.nodeId)) continue;
        keep.push(f);
      }
      findings.length = 0;
      findings.push(...keep, ...mapped.findings);
      // Analyzer edges replace native can-access edges from external principals to covered resources.
      const keepEdges: CloudEdge[] = edges.filter(
        (e) => !(e.relationship === "can-access" && covered.has(e.target) && e.source.startsWith("aws::iam::external-principal::")),
      );
      edges.length = 0;
      edges.push(...keepEdges, ...mapped.edges);
      for (const n of mapped.nodes) if (!known.has(n.id)) { nodes.push(n); known.add(n.id); }
    }
  }

  return { feeds, securityHubControls };
}
