import type { CheckRule } from "../types.js";

// --- network -----------------------------------------------------------------

const ADMIN_PORTS = [22, 3389];

export const naclUnrestrictedAdminPorts: CheckRule = {
  id: "ec2.nacl-unrestricted-admin-ports",
  version: 1,
  title: "Network ACL allows unrestricted ingress to SSH or RDP",
  severity: "medium",
  kind: "nacl-open-admin-ports",
  resourceTypes: ["aws::ec2::network-acl"],
  requires: ["ec2:network-acl"],
  controls: [
    { framework: "fsbp", id: "EC2.21" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Replace the allow-all inbound NACL entry with entries scoped to the ports and CIDRs the subnet actually needs; keep SSH/RDP behind a bastion or SSM.",
    cli: "aws ec2 replace-network-acl-entry --network-acl-id <acl> --ingress --rule-number 100 --protocol tcp --port-range From=443,To=443 --cidr-block 0.0.0.0/0 --rule-action allow",
  },
  check: (node) => {
    const entries = node.attributes["entries"] as Array<{ ruleNumber: number; egress: boolean; protocol: string; fromPort?: number; toPort?: number; cidr?: string; action: string }> | undefined;
    if (!Array.isArray(entries)) return { status: "not-applicable" };
    // NACL entries are evaluated in rule-number order; the first match wins.
    const inbound = entries.filter((e) => !e.egress && (e.cidr === "0.0.0.0/0" || e.cidr === "::/0")).sort((a, b) => a.ruleNumber - b.ruleNumber);
    const open: number[] = [];
    for (const port of ADMIN_PORTS) {
      const hit = inbound.find((e) => {
        const all = e.protocol === "-1";
        const tcp = e.protocol === "6" || e.protocol === "tcp";
        if (!all && !tcp) return false;
        const from = e.fromPort ?? 0;
        const to = e.toPort ?? 65535;
        return all || (from <= port && port <= to);
      });
      if (hit && hit.action === "allow") open.push(port);
    }
    return open.length ? { status: "fail", detail: `inbound allow from 0.0.0.0/0 covers port(s) ${open.join(", ")}` } : { status: "pass" };
  },
};

export const defaultSgOpen: CheckRule = {
  id: "ec2.default-sg-restricts-traffic",
  version: 1,
  title: "Default security group has ingress rules",
  severity: "medium",
  kind: "default-sg-open",
  resourceTypes: ["aws::ec2::security-group"],
  requires: ["ec2:security-group"],
  controls: [
    { framework: "fsbp", id: "EC2.2" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Remove every rule from the VPC default security group so an instance launched without an explicit group gets no access. (Egress is not collected yet; this checks ingress.)",
    cli: "aws ec2 revoke-security-group-ingress --group-id <default-sg> --ip-permissions \"$(aws ec2 describe-security-groups --group-ids <default-sg> --query 'SecurityGroups[0].IpPermissions')\"",
  },
  check: (node) => {
    if (node.name !== "default") return { status: "not-applicable" };
    const ingress = node.attributes["ingress"];
    return Array.isArray(ingress) && ingress.length > 0 ? { status: "fail", detail: `default SG has ${ingress.length} ingress rule(s)` } : { status: "pass" };
  },
};

export const instanceImdsv2: CheckRule = {
  id: "ec2.instance-imdsv2",
  version: 1,
  title: "EC2 instance does not require IMDSv2",
  severity: "high",
  kind: "instance-imdsv1",
  resourceTypes: ["aws::ec2::instance"],
  requires: ["ec2:instance"],
  controls: [
    { framework: "fsbp", id: "EC2.8" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Require IMDSv2 (HttpTokens=required). IMDSv1 lets an SSRF on the instance steal its role credentials.",
    cli: "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled",
    terraform: 'metadata_options {\n  http_tokens = "required"\n}',
  },
  check: (node) => {
    if (!("imdsv2Required" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["imdsv2Required"] === true ? { status: "pass" } : { status: "fail", detail: "HttpTokens is optional (IMDSv1 allowed)" };
  },
};

export const launchTemplateImdsv2: CheckRule = {
  id: "ec2.launch-template-imdsv2",
  version: 1,
  title: "Launch template does not require IMDSv2",
  severity: "medium",
  kind: "launch-template-imdsv1",
  resourceTypes: ["aws::ec2::launch-template"],
  requires: ["ec2:launch-template"],
  controls: [
    { framework: "fsbp", id: "AutoScaling.3" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Set MetadataOptions.HttpTokens=required in the launch template's default version so every instance it launches enforces IMDSv2.",
    terraform: 'metadata_options {\n  http_tokens = "required"\n}',
  },
  check: (node) => {
    if (!("imdsv2Required" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["imdsv2Required"] === true ? { status: "pass" } : { status: "fail", detail: "default version allows IMDSv1" };
  },
};

// --- load balancers --------------------------------------------------------------

export const albHttpRedirect: CheckRule = {
  id: "elbv2.alb-http-redirects-to-https",
  version: 1,
  title: "ALB HTTP listener does not redirect to HTTPS",
  severity: "medium",
  kind: "alb-plain-http",
  resourceTypes: ["aws::elbv2::load-balancer"],
  requires: ["elbv2:load-balancer"],
  controls: [
    { framework: "fsbp", id: "ELB.1" },
    { framework: "nist-csf-2", id: "PR.DS-02" },
  ],
  remediation: {
    text: "Change the HTTP listener's default action to a 301 redirect to HTTPS, or remove it.",
    cli: "aws elbv2 modify-listener --listener-arn <arn> --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'",
  },
  check: (node) => {
    if (node.attributes["lbType"] !== "application") return { status: "not-applicable" };
    const listeners = node.attributes["listeners"] as Array<{ port: number; protocol: string; redirectsToHttps: boolean }> | undefined;
    if (!Array.isArray(listeners)) return { status: "not-applicable" };
    const bad = listeners.filter((l) => l.protocol === "HTTP" && !l.redirectsToHttps);
    return bad.length ? { status: "fail", detail: `HTTP listener(s) on port ${bad.map((l) => l.port).join(", ")} serve without redirecting to HTTPS` } : { status: "pass" };
  },
};

export const albAccessLogs: CheckRule = {
  id: "elbv2.alb-access-logging",
  version: 1,
  title: "ALB access logging is disabled",
  severity: "low",
  kind: "alb-no-logging",
  resourceTypes: ["aws::elbv2::load-balancer"],
  requires: ["elbv2:load-balancer"],
  controls: [
    { framework: "fsbp", id: "ELB.5" },
    { framework: "nist-csf-2", id: "DE.CM-01" },
  ],
  remediation: {
    text: "Enable access logs to an S3 bucket with the ELB log-delivery bucket policy.",
    cli: "aws elbv2 modify-load-balancer-attributes --load-balancer-arn <arn> --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<bucket>",
  },
  check: (node) => {
    if (node.attributes["lbType"] !== "application" || !("accessLogsEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["accessLogsEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "access_logs.s3.enabled is false" };
  },
};

// --- containers -----------------------------------------------------------------------

export const ecsServicePublicIp: CheckRule = {
  id: "ecs.service-public-ip",
  version: 1,
  title: "ECS service assigns public IPs to tasks",
  severity: "high",
  kind: "ecs-public-ip",
  resourceTypes: ["aws::ecs::service"],
  requires: ["ecs:cluster"],
  controls: [
    { framework: "fsbp", id: "ECS.2" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Set assignPublicIp=DISABLED and run tasks in private subnets behind a load balancer or NAT.",
    cli: "aws ecs update-service --cluster <cluster> --service <svc> --network-configuration 'awsvpcConfiguration={subnets=[...],securityGroups=[...],assignPublicIp=DISABLED}'",
  },
  check: (node) => (node.attributes["assignPublicIp"] === true ? { status: "fail", detail: "assignPublicIp is ENABLED" } : { status: "pass" }),
};

export const eksPublicEndpoint: CheckRule = {
  id: "eks.public-endpoint",
  version: 1,
  title: "EKS control plane endpoint is open to the internet",
  severity: "high",
  kind: "eks-public-endpoint",
  resourceTypes: ["aws::eks::cluster"],
  requires: ["eks:cluster"],
  controls: [
    { framework: "fsbp", id: "EKS.1" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Enable private endpoint access and either disable public access or restrict publicAccessCidrs to your egress IPs.",
    cli: "aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=false",
  },
  check: (node) => {
    const cidrs = node.attributes["publicAccessCidrs"] as string[] | undefined;
    if (node.attributes["endpointPublicAccess"] !== true) return { status: "pass" };
    return Array.isArray(cidrs) && cidrs.some((c) => c === "0.0.0.0/0" || c === "::/0")
      ? { status: "fail", detail: "public endpoint reachable from 0.0.0.0/0" }
      : { status: "pass" };
  },
};

export const eksLogging: CheckRule = {
  id: "eks.control-plane-logging",
  version: 1,
  title: "EKS control plane logging is disabled",
  severity: "low",
  kind: "eks-no-logging",
  resourceTypes: ["aws::eks::cluster"],
  requires: ["eks:cluster"],
  controls: [
    { framework: "fsbp", id: "EKS.8" },
    { framework: "nist-csf-2", id: "DE.CM-09" },
  ],
  remediation: {
    text: "Enable at least the api, audit, and authenticator log types.",
    cli: "aws eks update-cluster-config --name <cluster> --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\"],\"enabled\":true}]}'",
  },
  check: (node) => (node.attributes["loggingEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "no control-plane log types enabled" }),
};

// --- messaging / data ---------------------------------------------------------------------

export const sqsEncrypted: CheckRule = {
  id: "sqs.queue-encrypted",
  version: 1,
  title: "SQS queue is not encrypted at rest",
  severity: "medium",
  kind: "sqs-unencrypted",
  resourceTypes: ["aws::sqs::queue"],
  requires: ["sqs:queue"],
  controls: [
    { framework: "fsbp", id: "SQS.1" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Enable SQS-managed SSE or a KMS key on the queue.",
    cli: "aws sqs set-queue-attributes --queue-url <url> --attributes SqsManagedSseEnabled=true",
  },
  check: (node) => (node.attributes["kmsEncrypted"] === true ? { status: "pass" } : { status: "fail", detail: "no server-side encryption" }),
};

export const snsEncrypted: CheckRule = {
  id: "sns.topic-encrypted",
  version: 1,
  title: "SNS topic is not encrypted at rest",
  severity: "medium",
  kind: "sns-unencrypted",
  resourceTypes: ["aws::sns::topic"],
  requires: ["sns:topic"],
  controls: [
    { framework: "fsbp", id: "SNS.1" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Set a KMS key on the topic (KmsMasterKeyId).",
    cli: "aws sns set-topic-attributes --topic-arn <arn> --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns",
  },
  check: (node) => (node.attributes["kmsEncrypted"] === true ? { status: "pass" } : { status: "fail", detail: "no KmsMasterKeyId" }),
};

export const dynamoPitr: CheckRule = {
  id: "dynamodb.pitr-enabled",
  version: 1,
  title: "DynamoDB table has point-in-time recovery disabled",
  severity: "low",
  kind: "dynamodb-no-pitr",
  resourceTypes: ["aws::dynamodb::table"],
  requires: ["dynamodb:table"],
  controls: [
    { framework: "fsbp", id: "DynamoDB.2" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Enable point-in-time recovery so the table can be restored to any second in the last 35 days.",
    cli: "aws dynamodb update-continuous-backups --table-name <t> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
  },
  check: (node) => {
    if (!("pitrEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["pitrEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "PITR disabled" };
  },
};

export const ecrScanOnPush: CheckRule = {
  id: "ecr.scan-on-push",
  version: 1,
  title: "ECR repository does not scan images on push",
  severity: "medium",
  kind: "ecr-no-scan",
  resourceTypes: ["aws::ecr::repository"],
  requires: ["ecr:repository"],
  controls: [
    { framework: "fsbp", id: "ECR.1" },
    { framework: "nist-csf-2", id: "DE.CM-09" },
  ],
  remediation: {
    text: "Enable scan-on-push (or enhanced scanning at the registry level).",
    cli: "aws ecr put-image-scanning-configuration --repository-name <repo> --image-scanning-configuration scanOnPush=true",
  },
  check: (node) => (node.attributes["scanOnPush"] === true ? { status: "pass" } : { status: "fail", detail: "scanOnPush is false" }),
};

export const ecrTagImmutability: CheckRule = {
  id: "ecr.tag-immutability",
  version: 1,
  title: "ECR repository allows mutable image tags",
  severity: "low",
  kind: "ecr-mutable-tags",
  resourceTypes: ["aws::ecr::repository"],
  requires: ["ecr:repository"],
  controls: [
    { framework: "fsbp", id: "ECR.2" },
    { framework: "nist-csf-2", id: "PR.PS-01" },
  ],
  remediation: {
    text: "Set image tag mutability to IMMUTABLE so a deployed tag cannot be silently repointed.",
    cli: "aws ecr put-image-tag-mutability --repository-name <repo> --image-tag-mutability IMMUTABLE",
  },
  check: (node) => (node.attributes["tagImmutability"] === true ? { status: "pass" } : { status: "fail", detail: "tags are MUTABLE" }),
};

export const ecrLifecycle: CheckRule = {
  id: "ecr.lifecycle-policy",
  version: 1,
  title: "ECR repository has no lifecycle policy",
  severity: "info",
  kind: "ecr-no-lifecycle",
  resourceTypes: ["aws::ecr::repository"],
  requires: ["ecr:repository"],
  controls: [
    { framework: "fsbp", id: "ECR.3" },
    { framework: "nist-csf-2", id: "PR.PS-01" },
  ],
  remediation: {
    text: "Add a lifecycle policy that expires untagged and old images.",
    cli: "aws ecr put-lifecycle-policy --repository-name <repo> --lifecycle-policy-text file://lifecycle.json",
  },
  check: (node) => (node.attributes["lifecyclePolicy"] === true ? { status: "pass" } : { status: "fail", detail: "no lifecycle policy" }),
};

export const efsEncrypted: CheckRule = {
  id: "efs.file-system-encrypted",
  version: 1,
  title: "EFS file system is not encrypted at rest",
  severity: "medium",
  kind: "efs-unencrypted",
  resourceTypes: ["aws::efs::file-system"],
  requires: ["efs:file-system"],
  controls: [
    { framework: "fsbp", id: "EFS.1" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "EFS encryption is set at creation: create an encrypted file system and migrate the data with DataSync.",
  },
  check: (node) => (node.attributes["encrypted"] === true ? { status: "pass" } : { status: "fail", detail: "Encrypted is false" }),
};

// --- edge ------------------------------------------------------------------------------

export const cloudFrontViewerHttps: CheckRule = {
  id: "cloudfront.viewer-protocol-https",
  version: 1,
  title: "CloudFront distribution serves plain HTTP to viewers",
  severity: "medium",
  kind: "cloudfront-allow-http",
  resourceTypes: ["aws::cloudfront::distribution"],
  requires: ["cloudfront:distribution"],
  controls: [
    { framework: "fsbp", id: "CloudFront.3" },
    { framework: "nist-csf-2", id: "PR.DS-02" },
  ],
  remediation: {
    text: "Set the default cache behavior's viewer protocol policy to redirect-to-https or https-only.",
  },
  check: (node) => {
    if (node.attributes["enabled"] !== true) return { status: "not-applicable" };
    return node.attributes["viewerProtocolPolicy"] === "allow-all" ? { status: "fail", detail: "viewer protocol policy is allow-all" } : { status: "pass" };
  },
};

export const cloudFrontLogging: CheckRule = {
  id: "cloudfront.access-logging",
  version: 1,
  title: "CloudFront distribution has no access logging",
  severity: "low",
  kind: "cloudfront-no-logging",
  resourceTypes: ["aws::cloudfront::distribution"],
  requires: ["cloudfront:distribution"],
  controls: [
    { framework: "fsbp", id: "CloudFront.5" },
    { framework: "nist-csf-2", id: "DE.CM-01" },
  ],
  remediation: { text: "Enable standard logging to an S3 bucket (or CloudWatch Logs with standard logging v2)." },
  check: (node) => (node.attributes["loggingEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "logging disabled" }),
};

export const apiGatewayLogging: CheckRule = {
  id: "apigateway.stage-logging",
  version: 1,
  title: "API Gateway stage has execution logging off",
  severity: "low",
  kind: "apigw-no-logging",
  resourceTypes: ["aws::apigateway::rest-api"],
  requires: ["apigateway:rest-api"],
  controls: [
    { framework: "fsbp", id: "APIGateway.1" },
    { framework: "nist-csf-2", id: "DE.CM-01" },
  ],
  remediation: {
    text: "Turn on execution logging (INFO or ERROR) for every stage.",
    cli: "aws apigateway update-stage --rest-api-id <id> --stage-name <stage> --patch-operations op=replace,path=/*/*/logging/loglevel,value=INFO",
  },
  check: (node) => {
    const stages = node.attributes["stages"] as Array<{ name: string; loggingEnabled: boolean }> | undefined;
    if (!Array.isArray(stages) || stages.length === 0) return { status: "not-applicable" };
    const off = stages.filter((s) => !s.loggingEnabled).map((s) => s.name);
    return off.length ? { status: "fail", detail: `stage(s) without logging: ${off.join(", ")}` } : { status: "pass" };
  },
};

// --- RDS ------------------------------------------------------------------------------

export const rdsSnapshotPublic: CheckRule = {
  id: "rds.snapshot-public",
  version: 1,
  title: "RDS snapshot is publicly restorable",
  severity: "critical",
  kind: "rds-snapshot-public",
  resourceTypes: ["aws::rds::db-snapshot"],
  requires: ["rds:db-snapshot"],
  controls: [
    { framework: "fsbp", id: "RDS.1" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Remove 'all' from the snapshot's restore attribute. A public snapshot hands the whole database to anyone with an AWS account.",
    cli: "aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all",
  },
  check: (node) => (node.attributes["public"] === true ? { status: "fail", detail: "restore attribute includes 'all'" } : { status: "pass" }),
};

export const rdsClusterEncrypted: CheckRule = {
  id: "rds.cluster-storage-encrypted",
  version: 1,
  title: "RDS cluster storage is not encrypted",
  severity: "medium",
  kind: "rds-cluster-unencrypted",
  resourceTypes: ["aws::rds::db-cluster"],
  requires: ["rds:db-cluster"],
  controls: [
    { framework: "fsbp", id: "RDS.27" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: { text: "Cluster encryption is set at creation: snapshot, copy encrypted, restore, cut over." },
  check: (node) => {
    if (!("storageEncrypted" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["storageEncrypted"] === true ? { status: "pass" } : { status: "fail", detail: "StorageEncrypted is false" };
  },
};

export const trancheBRules: CheckRule[] = [
  naclUnrestrictedAdminPorts, defaultSgOpen, instanceImdsv2, launchTemplateImdsv2,
  albHttpRedirect, albAccessLogs,
  ecsServicePublicIp, eksPublicEndpoint, eksLogging,
  sqsEncrypted, snsEncrypted, dynamoPitr, ecrScanOnPush, ecrTagImmutability, ecrLifecycle, efsEncrypted,
  cloudFrontViewerHttps, cloudFrontLogging, apiGatewayLogging,
  rdsSnapshotPublic, rdsClusterEncrypted,
];
