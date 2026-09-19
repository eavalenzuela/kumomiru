import type { CheckRule } from "../types.js";

export const rdsPubliclyAccessible: CheckRule = {
  id: "rds.instance-publicly-accessible",
  version: 1,
  title: "RDS instance is publicly accessible",
  severity: "critical",
  kind: "rds-public",
  resourceTypes: ["aws::rds::db-instance"],
  requires: ["rds:db-instance"],
  controls: [
    { framework: "fsbp", id: "RDS.2" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Set PubliclyAccessible to false and place the instance in private subnets; reach it through the VPC (or a bastion / SSM port forward).",
    cli: "aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible --apply-immediately",
    terraform: "publicly_accessible = false",
  },
  check: (node) =>
    node.attributes["publiclyAccessible"] === true
      ? { status: "fail", detail: "PubliclyAccessible is true" }
      : { status: "pass" },
};

export const rdsRules: CheckRule[] = [rdsPubliclyAccessible];
