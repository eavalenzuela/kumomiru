import type { Finding, Severity } from "@kumomiru/graph";
import type { AsffFinding } from "../aws-live/client.js";

/**
 * Map Security Hub findings (ASFF) to kumomiru findings.
 *
 * - Control findings (Security Hub's own FSBP/CIS checks) carry a
 *   SecurityControlId; FAILED ones become findings with `ruleId
 *   securityhub.<control>` and an FSBP control ref. PASSED ones are not
 *   findings, but their control ids are recorded (see `coveredControls`) so
 *   the roll-up knows Security Hub reported on the control.
 * - Findings from other products routed through Security Hub (GuardDuty,
 *   Inspector, Macie, ...) become findings with `ruleId securityhub.<product>`
 *   and no control ref.
 *
 * Ids are the Security Hub finding ids (stable per finding), prefixed so they
 * can never collide with native ids. The Security Hub finding id is also
 * kept in `externalId` for round-tripping to the console.
 */
export interface AsffMapping {
  findings: Finding[];
  /** FSBP control ids Security Hub reported (passed or failed). */
  coveredControls: string[];
}

const SEVERITY: Record<string, Severity> = {
  INFORMATIONAL: "info",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

export function mapAsffFindings(raw: readonly AsffFinding[], knownNodeIds: ReadonlySet<string>): AsffMapping {
  const findings: Finding[] = [];
  const covered = new Set<string>();
  for (const f of raw) {
    const control = f.securityControlId;
    if (control) covered.add(control);
    const isControlFinding = Boolean(control);
    if (isControlFinding && f.complianceStatus !== "FAILED" && f.complianceStatus !== "WARNING") continue;
    if (!isControlFinding && f.workflowStatus && !["NEW", "NOTIFIED"].includes(f.workflowStatus)) continue;

    const nodeId = f.resourceIds.find((r) => knownNodeIds.has(r));
    const product = (f.productName ?? "securityhub").toLowerCase().replace(/[^a-z0-9]+/g, "-");
    findings.push({
      id: `f-sh-${f.id.replace(/[^A-Za-z0-9]+/g, "-").slice(-64)}`,
      severity: SEVERITY[f.severityLabel ?? ""] ?? "medium",
      kind: control ? `securityhub-${control.toLowerCase()}` : `securityhub-${product}`,
      ...(nodeId ? { nodeId } : {}),
      title: f.title,
      detail: [f.description ?? "", f.remediationText ?? ""].filter(Boolean).join(" ") || f.title,
      ruleId: control ? `securityhub.${control}` : `securityhub.${product}`,
      source: "securityhub",
      controls: control ? [{ framework: "fsbp", id: control }] : [],
      ...(f.remediationText || f.remediationUrl
        ? { remediation: { text: [f.remediationText, f.remediationUrl].filter(Boolean).join(" ") } }
        : {}),
      ...(f.resourceTypes[0] ? { resourceType: asffTypeToKumomiru(f.resourceTypes[0]) } : {}),
      externalId: f.id,
      ...(f.updatedAt ? { observedAt: f.updatedAt } : {}),
      evidence: {
        resourceIds: f.resourceIds,
        ...(f.complianceStatus ? { complianceStatus: f.complianceStatus } : {}),
        ...(f.workflowStatus ? { workflowStatus: f.workflowStatus } : {}),
        ...(f.generatorId ? { generatorId: f.generatorId } : {}),
      },
    });
  }
  return { findings, coveredControls: [...covered].sort() };
}

/** ASFF resource types ("AwsS3Bucket") → kumomiru node types, best effort. */
export function asffTypeToKumomiru(t: string): string {
  const map: Record<string, string> = {
    AwsS3Bucket: "aws::s3::bucket",
    AwsEc2Instance: "aws::ec2::instance",
    AwsEc2SecurityGroup: "aws::ec2::security-group",
    AwsEc2Vpc: "aws::ec2::vpc",
    AwsEc2Subnet: "aws::ec2::subnet",
    AwsEc2Volume: "aws::ec2::volume",
    AwsRdsDbInstance: "aws::rds::db-instance",
    AwsRdsDbCluster: "aws::rds::db-cluster",
    AwsRdsDbSnapshot: "aws::rds::db-snapshot",
    AwsLambdaFunction: "aws::lambda::function",
    AwsIamRole: "aws::iam::role",
    AwsIamUser: "aws::iam::user",
    AwsKmsKey: "aws::kms::key",
    AwsCloudTrailTrail: "aws::cloudtrail::trail",
    AwsSecretsManagerSecret: "aws::secretsmanager::secret",
    AwsSqsQueue: "aws::sqs::queue",
    AwsSnsTopic: "aws::sns::topic",
    AwsDynamoDbTable: "aws::dynamodb::table",
    AwsEcrRepository: "aws::ecr::repository",
    AwsEcsCluster: "aws::ecs::cluster",
    AwsEcsService: "aws::ecs::service",
    AwsEcsTaskDefinition: "aws::ecs::task-definition",
    AwsEksCluster: "aws::eks::cluster",
    AwsElbv2LoadBalancer: "aws::elbv2::load-balancer",
    AwsEfsFileSystem: "aws::efs::file-system",
    AwsCloudFrontDistribution: "aws::cloudfront::distribution",
    AwsApiGatewayRestApi: "aws::apigateway::rest-api",
    AwsAutoScalingAutoScalingGroup: "aws::autoscaling::group",
    AwsEc2LaunchTemplate: "aws::ec2::launch-template",
    AwsEc2NetworkAcl: "aws::ec2::network-acl",
    AwsAccount: "aws::account",
  };
  return map[t] ?? `asff::${t}`;
}
