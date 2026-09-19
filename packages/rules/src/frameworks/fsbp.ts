import type { Catalogue } from "./types.js";

/**
 * AWS Foundational Security Best Practices — the subset of controls kumomiru
 * rules map to today, plus a few the roadmap's next tranche targets so the
 * compliance report shows them as not-assessed rather than absent. Titles
 * follow the Security Hub control reference; AWS revises the standard
 * quarterly, so this catalogue is versioned and reviewed in-house.
 */
export const FSBP: Catalogue = {
  framework: "fsbp",
  name: "AWS Foundational Security Best Practices v1.0.0",
  version: "2026-09",
  controls: [
    { id: "EC2.13", title: "Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22" },
    { id: "EC2.14", title: "Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389" },
    { id: "EC2.15", title: "EC2 subnets should not automatically assign public IP addresses" },
    { id: "EC2.18", title: "Security groups should only allow unrestricted incoming traffic for authorized ports" },
    { id: "EC2.19", title: "Security groups should not allow unrestricted access to ports with high risk" },
    { id: "RDS.2", title: "RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible configuration" },
    { id: "EC2.1", title: "EBS snapshots should not be publicly restorable" },
    { id: "EC2.3", title: "Attached EBS volumes should be encrypted at rest" },
    { id: "EC2.6", title: "VPC flow logging should be enabled in all VPCs" },
    { id: "EC2.7", title: "EBS default encryption should be enabled" },
    { id: "RDS.3", title: "RDS DB instances should have encryption at-rest enabled" },
    { id: "IAM.3", title: "IAM users' access keys should be rotated every 90 days or less" },
    { id: "IAM.4", title: "IAM root user access key should not exist" },
    { id: "IAM.5", title: "MFA should be enabled for all IAM users that have a console password" },
    { id: "IAM.7", title: "Password policies for IAM users should have strong configurations" },
    { id: "IAM.8", title: "Unused IAM user credentials should be removed" },
    { id: "IAM.9", title: "MFA should be enabled for the root user" },
    { id: "S3.1", title: "S3 general purpose buckets should have block public access settings enabled" },
    { id: "S3.2", title: "S3 general purpose buckets should block public read access" },
    { id: "S3.5", title: "S3 general purpose buckets should require requests to use SSL" },
    { id: "S3.8", title: "S3 general purpose buckets should block public access" },
    { id: "S3.9", title: "S3 general purpose buckets should have server access logging enabled" },
    { id: "KMS.4", title: "AWS KMS key rotation should be enabled" },
    { id: "CloudTrail.1", title: "CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events" },
    { id: "CloudTrail.2", title: "CloudTrail should have encryption at-rest enabled" },
    { id: "CloudTrail.4", title: "CloudTrail log file validation should be enabled" },
    { id: "Config.1", title: "AWS Config should be enabled and use the service-linked role for resource recording" },
    { id: "GuardDuty.1", title: "GuardDuty should be enabled" },
    { id: "Lambda.1", title: "Lambda function policies should prohibit public access" },
    { id: "SecretsManager.1", title: "Secrets Manager secrets should have automatic rotation enabled" },
    // Not yet mapped (Phase 3 tranche B collectors): visible as not-assessed.
    { id: "IAM.6", title: "Hardware MFA should be enabled for the root user" },
    { id: "ELB.1", title: "Application Load Balancer should be configured to redirect all HTTP requests to HTTPS" },
    { id: "ECS.8", title: "Secrets should not be passed as container environment variables" },
    { id: "SQS.1", title: "Amazon SQS queues should be encrypted at rest" },
    { id: "SNS.1", title: "SNS topics should be encrypted at-rest using AWS KMS" },
  ],
};
