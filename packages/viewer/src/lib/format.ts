/** Small presentation helpers shared by the inspector and legend. */

const TYPE_LABELS: Record<string, string> = {
  "aws::account": "Account",
  "aws::region": "Region",
  "aws::ec2::vpc": "VPC",
  "aws::ec2::subnet": "Subnet",
  "aws::ec2::instance": "EC2 instance",
  "aws::ec2::internet-gateway": "Internet gateway",
  "aws::ec2::security-group": "Security group",
  "aws::rds::db-instance": "RDS instance",
  "aws::lambda::function": "Lambda function",
  "aws::dynamodb::table": "DynamoDB table",
  "aws::secretsmanager::secret": "Secrets Manager secret",
  "aws::iam::role": "IAM role",
  "aws::iam::user": "IAM user",
  "aws::iam::external-principal": "External principal",
  "aws::s3::bucket": "S3 bucket",
  "aws::kms::key": "KMS key",
  "aws::ec2::volume": "EBS volume",
  "aws::ec2::snapshot": "EBS snapshot",
  "aws::cloudtrail::trail": "CloudTrail trail",
};

/** "aws::ec2::instance" → "EC2 instance"; unknown types fall back to the tail. */
export function humanizeType(type: string): string {
  if (TYPE_LABELS[type]) return TYPE_LABELS[type];
  const tail = type.split("::").pop() ?? type;
  return tail.replace(/-/g, " ");
}

/** Format an attribute value for display without ever expanding secrets. */
export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
