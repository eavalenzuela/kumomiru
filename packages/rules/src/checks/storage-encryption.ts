import type { CheckRule } from "../types.js";

export const ebsVolumeEncrypted: CheckRule = {
  id: "ec2.ebs-volume-encrypted",
  version: 1,
  title: "Attached EBS volume is not encrypted",
  severity: "medium",
  kind: "ebs-unencrypted",
  resourceTypes: ["aws::ec2::volume"],
  requires: ["ec2:volume"],
  controls: [
    { framework: "fsbp", id: "EC2.3" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Volumes cannot be encrypted in place: snapshot it, copy the snapshot with encryption, create a new volume from the copy, and swap it in. Enable EBS default encryption so new volumes never start unencrypted.",
    cli: "aws ec2 copy-snapshot --source-snapshot-id <snap> --source-region <region> --encrypted",
  },
  check: (node) =>
    node.attributes["attached"] !== true
      ? { status: "not-applicable" }
      : node.attributes["encrypted"] === true
        ? { status: "pass" }
        : { status: "fail", detail: "attached volume is unencrypted" },
};

export const ebsSnapshotNotPublic: CheckRule = {
  id: "ec2.ebs-snapshot-public",
  version: 1,
  title: "EBS snapshot is publicly restorable",
  severity: "critical",
  kind: "ebs-snapshot-public",
  resourceTypes: ["aws::ec2::snapshot"],
  requires: ["ec2:snapshot"],
  controls: [
    { framework: "fsbp", id: "EC2.1" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Remove the 'all' group from the snapshot's createVolumePermission. Anyone with an AWS account can otherwise copy the disk.",
    cli: "aws ec2 modify-snapshot-attribute --snapshot-id <snap> --attribute createVolumePermission --operation-type remove --group-names all",
  },
  check: (node) =>
    node.attributes["public"] === true ? { status: "fail", detail: "createVolumePermission includes group 'all'" } : { status: "pass" },
};

export const ebsDefaultEncryption: CheckRule = {
  id: "ec2.ebs-default-encryption",
  version: 1,
  title: "EBS default encryption is off in this region",
  severity: "medium",
  kind: "ebs-default-encryption-off",
  resourceTypes: ["aws::region"],
  requires: ["account:region-settings"],
  controls: [
    { framework: "fsbp", id: "EC2.7" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Enable EBS encryption by default for the region so every new volume and snapshot copy is encrypted.",
    cli: "aws ec2 enable-ebs-encryption-by-default --region <region>",
  },
  check: (node) => {
    if (!("ebsEncryptionByDefault" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["ebsEncryptionByDefault"] === true ? { status: "pass" } : { status: "fail", detail: "EBS encryption by default is disabled" };
  },
};

export const vpcFlowLogs: CheckRule = {
  id: "ec2.vpc-flow-logs",
  version: 1,
  title: "VPC has no flow logs",
  severity: "medium",
  kind: "vpc-no-flow-logs",
  resourceTypes: ["aws::ec2::vpc"],
  requires: ["ec2:flow-log"],
  controls: [
    { framework: "fsbp", id: "EC2.6" },
    { framework: "nist-csf-2", id: "DE.CM-01" },
  ],
  remediation: {
    text: "Create a VPC flow log (REJECT traffic at minimum) to CloudWatch Logs or S3.",
    cli: "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type REJECT --log-destination-type s3 --log-destination arn:aws:s3:::<log-bucket>",
  },
  check: (node) => {
    if (!("flowLogsEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["flowLogsEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "no flow log configured" };
  },
};

export const rdsStorageEncrypted: CheckRule = {
  id: "rds.instance-storage-encrypted",
  version: 1,
  title: "RDS instance storage is not encrypted",
  severity: "medium",
  kind: "rds-unencrypted",
  resourceTypes: ["aws::rds::db-instance"],
  requires: ["rds:encryption"],
  controls: [
    { framework: "fsbp", id: "RDS.3" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "RDS storage encryption cannot be enabled in place: snapshot, copy the snapshot with a KMS key, restore, then cut over.",
    cli: "aws rds copy-db-snapshot --source-db-snapshot-identifier <snap> --target-db-snapshot-identifier <snap>-enc --kms-key-id <key>",
  },
  check: (node) => {
    if (!("storageEncrypted" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["storageEncrypted"] === true ? { status: "pass" } : { status: "fail", detail: "StorageEncrypted is false" };
  },
};

export const kmsKeyRotation: CheckRule = {
  id: "kms.key-rotation",
  version: 1,
  title: "Customer-managed KMS key has rotation disabled",
  severity: "medium",
  kind: "kms-no-rotation",
  resourceTypes: ["aws::kms::key"],
  requires: ["kms:key"],
  controls: [
    { framework: "fsbp", id: "KMS.4" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Enable automatic annual rotation on the key.",
    cli: "aws kms enable-key-rotation --key-id <key-id>",
    terraform: "enable_key_rotation = true",
  },
  check: (node) => {
    if (node.attributes["manager"] !== "CUSTOMER" || node.attributes["enabled"] !== true) return { status: "not-applicable" };
    if (!("rotationEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["rotationEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "automatic key rotation is disabled" };
  },
};

export const storageEncryptionRules: CheckRule[] = [ebsVolumeEncrypted, ebsSnapshotNotPublic, ebsDefaultEncryption, vpcFlowLogs, rdsStorageEncrypted, kmsKeyRotation];
