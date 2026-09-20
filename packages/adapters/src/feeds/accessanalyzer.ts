import type { CloudEdge, CloudNode, Finding } from "@kumomiru/graph";
import type { AccessAnalyzerFinding } from "../aws-live/client.js";

/**
 * Map IAM Access Analyzer external-access findings to the same shapes the
 * native resource-policy pass produces — `can-access` iam edges from an
 * external-principal node and `public-resource` / `external-can-access`
 * findings — attributed `source: "accessanalyzer"`. Access Analyzer reasons
 * about the full policy set (SCPs, boundaries, conditions) and is therefore
 * authoritative: the caller drops native findings for any resource the
 * analyzer reported on.
 */
export interface AnalyzerMapping {
  nodes: CloudNode[];
  edges: CloudEdge[];
  findings: Finding[];
  /** Resource ARNs the analyzer reported on (native findings superseded). */
  coveredResources: string[];
}

export function mapAccessAnalyzerFindings(
  raw: readonly AccessAnalyzerFinding[],
  knownNodeIds: ReadonlySet<string>,
  externalParent: string,
): AnalyzerMapping {
  const nodes = new Map<string, CloudNode>();
  const edges: CloudEdge[] = [];
  const findings: Finding[] = [];
  const covered = new Set<string>();

  for (const f of raw) {
    if (f.status && f.status !== "ACTIVE") continue;
    covered.add(f.resourceArn);
    const principal = f.isPublic ? "*" : (f.principal ?? "unknown");
    const srcId = `aws::iam::external-principal::${principal}`;
    if (!nodes.has(srcId)) {
      const acct = principal.match(/^arn:[a-z-]+:iam::(\d{12}):/)?.[1] ?? (/^\d{12}$/.test(principal) ? principal : undefined);
      nodes.set(srcId, {
        id: srcId,
        type: "aws::iam::external-principal",
        name: principal === "*" ? "any principal (*)" : acct ? `external-account-${acct}` : principal,
        account: acct ?? "external",
        parent: externalParent,
        tags: {},
        attributes: { external: true, principal },
      });
    }
    const action = f.actions[0] ?? "*";
    const conds = f.conditionKeys;
    if (knownNodeIds.has(f.resourceArn)) {
      edges.push({
        id: `e-access-aa-${hashId(`${srcId}->${f.resourceArn}`)}`,
        source: srcId,
        target: f.resourceArn,
        relationship: "can-access",
        lens: "iam",
        attributes: {
          action,
          actions: f.actions,
          external: true,
          ...(f.isPublic ? { public: true } : {}),
          ...(conds.length ? { conditional: true, conditions: conds } : {}),
          source: "accessanalyzer",
        },
      });
    }
    const gate = conds.length ? ` Gated by condition(s) ${conds.join(", ")}.` : "";
    findings.push({
      id: `f-aa-${f.id.replace(/[^A-Za-z0-9]+/g, "-").slice(-64)}`,
      severity: f.isPublic ? (conds.length ? "high" : "critical") : (conds.length ? "medium" : "high"),
      kind: f.isPublic ? "public-resource" : "external-can-access",
      ...(knownNodeIds.has(f.resourceArn) ? { nodeId: f.resourceArn } : {}),
      title: f.isPublic ? "Resource is publicly accessible (Access Analyzer)" : "External principal can access a resource (Access Analyzer)",
      detail: `${f.resourceArn} allows ${f.actions.join(", ") || "access"} to ${f.isPublic ? 'principal "*"' : `external principal ${principal}`}.${gate}`,
      source: "accessanalyzer",
      resourceType: analyzerTypeToKumomiru(f.resourceType),
      externalId: f.id,
      ...(f.updatedAt ? { observedAt: f.updatedAt } : {}),
      evidence: { actions: f.actions, ...(f.principal ? { principal: f.principal } : {}) },
    });
  }
  return { nodes: [...nodes.values()], edges, findings, coveredResources: [...covered].sort() };
}

function analyzerTypeToKumomiru(t: string): string {
  const map: Record<string, string> = {
    "AWS::S3::Bucket": "aws::s3::bucket",
    "AWS::IAM::Role": "aws::iam::role",
    "AWS::KMS::Key": "aws::kms::key",
    "AWS::Lambda::Function": "aws::lambda::function",
    "AWS::SQS::Queue": "aws::sqs::queue",
    "AWS::SNS::Topic": "aws::sns::topic",
    "AWS::SecretsManager::Secret": "aws::secretsmanager::secret",
    "AWS::EFS::FileSystem": "aws::efs::file-system",
    "AWS::ECR::Repository": "aws::ecr::repository",
    "AWS::RDS::DBSnapshot": "aws::rds::db-snapshot",
    "AWS::RDS::DBClusterSnapshot": "aws::rds::db-snapshot",
    "AWS::EC2::Snapshot": "aws::ec2::snapshot",
    "AWS::DynamoDB::Table": "aws::dynamodb::table",
  };
  return map[t] ?? t;
}

function hashId(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (h * 33) ^ s.charCodeAt(i);
  return (h >>> 0).toString(36);
}
