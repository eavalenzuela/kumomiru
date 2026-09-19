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
  "aws::ec2::route-table": "Route table",
  "aws::ec2::nat-gateway": "NAT gateway",
  "aws::ec2::vpc-peering": "VPC peering",
  "aws::ec2::vpc-endpoint": "VPC endpoint",
  "aws::ec2::network-acl": "Network ACL",
  "aws::elbv2::load-balancer": "Load balancer",
  "aws::ecs::cluster": "ECS cluster",
  "aws::ecs::service": "ECS service",
  "aws::ecs::task-definition": "ECS task definition",
  "aws::eks::cluster": "EKS cluster",
  "aws::sqs::queue": "SQS queue",
  "aws::sns::topic": "SNS topic",
  "aws::ecr::repository": "ECR repository",
  "aws::autoscaling::group": "Auto Scaling group",
  "aws::ec2::launch-template": "Launch template",
  "aws::efs::file-system": "EFS file system",
  "aws::cloudfront::distribution": "CloudFront distribution",
  "aws::apigateway::rest-api": "API Gateway REST API",
  "aws::rds::db-cluster": "RDS cluster",
  "aws::rds::db-snapshot": "RDS snapshot",
  "aws::ssm::parameter": "SSM parameter",
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
