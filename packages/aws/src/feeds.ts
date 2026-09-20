/**
 * Managed-feed SDK collectors: Security Hub and IAM Access Analyzer. Both
 * are regional and optional; a disabled service yields `enabled: false` so
 * native rules cover the same ground.
 */
import { SecurityHubClient, DescribeHubCommand, GetFindingsCommand, type AwsSecurityFinding } from "@aws-sdk/client-securityhub";
import { AccessAnalyzerClient, ListAnalyzersCommand, ListFindingsV2Command, GetFindingV2Command } from "@aws-sdk/client-accessanalyzer";
import type { AccessAnalyzerFeed, AccessAnalyzerFinding, AsffFinding, SecurityHubFeed } from "@kumomiru/adapters";

export const FEED_ACTIONS = [
  "securityhub:DescribeHub",
  "securityhub:GetFindings",
  "access-analyzer:ListAnalyzers",
  "access-analyzer:ListFindingsV2",
  "access-analyzer:GetFindingV2",
] as const;

type Cfg = { region: string; credentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string } };

function isDisabled(err: unknown): boolean {
  const name = (err as { name?: string })?.name ?? "";
  return /InvalidAccessException|ResourceNotFoundException|AccessDeniedException|NotFound/.test(name);
}

async function mapConcurrent<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function projectAsff(f: AwsSecurityFinding): AsffFinding {
  return {
    id: f.Id ?? "",
    ...(f.ProductName ? { productName: f.ProductName } : {}),
    ...(f.GeneratorId ? { generatorId: f.GeneratorId } : {}),
    title: f.Title ?? f.Id ?? "",
    ...(f.Description ? { description: f.Description } : {}),
    ...(f.Severity?.Label ? { severityLabel: f.Severity.Label } : {}),
    ...(f.Compliance?.Status ? { complianceStatus: f.Compliance.Status } : {}),
    ...(f.Compliance?.SecurityControlId ? { securityControlId: f.Compliance.SecurityControlId } : {}),
    resourceIds: (f.Resources ?? []).map((r) => r.Id ?? "").filter(Boolean),
    resourceTypes: (f.Resources ?? []).map((r) => r.Type ?? "").filter(Boolean),
    ...(f.Workflow?.Status ? { workflowStatus: f.Workflow.Status } : {}),
    ...(f.UpdatedAt ? { updatedAt: f.UpdatedAt } : {}),
    ...(f.Remediation?.Recommendation?.Text ? { remediationText: f.Remediation.Recommendation.Text } : {}),
    ...(f.Remediation?.Recommendation?.Url ? { remediationUrl: f.Remediation.Recommendation.Url } : {}),
  };
}

export function securityHubCollector(cfg: Cfg) {
  const sh = new SecurityHubClient(cfg);
  return {
    async securityHubFindings(): Promise<SecurityHubFeed> {
      try {
        await sh.send(new DescribeHubCommand({}));
      } catch (err) {
        if (isDisabled(err)) return { enabled: false, findings: [] };
        throw err;
      }
      // Active findings only. Control findings (PASSED and FAILED) come from
      // Security Hub itself; product findings (GuardDuty, Inspector, ...) are
      // kept when their workflow is NEW or NOTIFIED. Suppressed / resolved
      // records are left to the console.
      const findings: AsffFinding[] = [];
      let token: string | undefined;
      let pages = 0;
      do {
        const res = await sh.send(
          new GetFindingsCommand({
            Filters: {
              RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
              WorkflowStatus: [
                { Value: "NEW", Comparison: "EQUALS" },
                { Value: "NOTIFIED", Comparison: "EQUALS" },
                { Value: "RESOLVED", Comparison: "EQUALS" },
              ],
            },
            MaxResults: 100,
            ...(token ? { NextToken: token } : {}),
          }),
        );
        for (const f of res.Findings ?? []) {
          const p = projectAsff(f);
          // RESOLVED is only interesting for PASSED control findings (coverage).
          if (p.workflowStatus === "RESOLVED" && p.complianceStatus !== "PASSED") continue;
          findings.push(p);
        }
        token = res.NextToken;
        pages++;
      } while (token && pages < 500);
      return { enabled: true, findings };
    },
  };
}

export function accessAnalyzerCollector(cfg: Cfg) {
  const aa = new AccessAnalyzerClient(cfg);
  return {
    async accessAnalyzerFindings(): Promise<AccessAnalyzerFeed> {
      const analyzers = (await aa.send(new ListAnalyzersCommand({}))).analyzers ?? [];
      const active = analyzers.filter((a) => a.status === "ACTIVE" && a.arn);
      if (active.length === 0) return { enabled: false, findings: [] };
      const out: AccessAnalyzerFinding[] = [];
      for (const analyzer of active) {
        const ids: string[] = [];
        let token: string | undefined;
        do {
          const res = await aa.send(new ListFindingsV2Command({
            analyzerArn: analyzer.arn!,
            filter: { status: { eq: ["ACTIVE"] } },
            ...(token ? { nextToken: token } : {}),
          }));
          for (const f of res.findings ?? []) if (f.id) ids.push(f.id);
          token = res.nextToken;
        } while (token);
        const details = await mapConcurrent(ids, 6, async (id) => {
          try {
            return await aa.send(new GetFindingV2Command({ analyzerArn: analyzer.arn!, id }));
          } catch {
            return undefined;
          }
        });
        for (const d of details) {
          if (!d?.id) continue;
          const ext = (d.findingDetails ?? []).map((x) => x.externalAccessDetails).find(Boolean);
          const principalObj = ext?.principal ?? {};
          const principal = principalObj["AWS"] ?? principalObj["Federated"] ?? principalObj["Service"] ?? Object.values(principalObj)[0];
          out.push({
            id: d.id,
            resourceArn: d.resource ?? "",
            resourceType: d.resourceType ?? "",
            ...(principal ? { principal } : {}),
            isPublic: ext?.isPublic ?? false,
            actions: ext?.action ?? [],
            conditionKeys: Object.keys(ext?.condition ?? {}),
            status: d.status ?? "ACTIVE",
            ...(d.updatedAt ? { updatedAt: d.updatedAt.toISOString() } : {}),
          });
        }
      }
      return { enabled: true, findings: out };
    },
  };
}
