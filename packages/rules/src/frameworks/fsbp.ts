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
    // Next tranche (Phase 3 collectors): listed so coverage gaps are visible.
    { id: "IAM.4", title: "IAM root user access key should not exist" },
    { id: "IAM.6", title: "Hardware MFA should be enabled for the root user" },
    { id: "S3.1", title: "S3 general purpose buckets should have block public access settings enabled" },
    { id: "S3.8", title: "S3 general purpose buckets should block public access" },
    { id: "EC2.7", title: "EBS default encryption should be enabled" },
    { id: "KMS.4", title: "AWS KMS key rotation should be enabled" },
    { id: "CloudTrail.1", title: "CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events" },
    { id: "Lambda.1", title: "Lambda function policies should prohibit public access" },
    { id: "SecretsManager.1", title: "Secrets Manager secrets should have automatic rotation enabled" },
  ],
};
