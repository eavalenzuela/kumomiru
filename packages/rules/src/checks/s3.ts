import type { CheckRule } from "../types.js";

const BUCKET = "aws::s3::bucket";
const ACCOUNT = "aws::account";

interface Pab { blockPublicAcls: boolean; ignorePublicAcls: boolean; blockPublicPolicy: boolean; restrictPublicBuckets: boolean }

function pabGaps(pab: Pab | null | undefined): string[] {
  if (!pab) return ["no public access block configuration"];
  const gaps: string[] = [];
  if (!pab.blockPublicAcls) gaps.push("BlockPublicAcls off");
  if (!pab.ignorePublicAcls) gaps.push("IgnorePublicAcls off");
  if (!pab.blockPublicPolicy) gaps.push("BlockPublicPolicy off");
  if (!pab.restrictPublicBuckets) gaps.push("RestrictPublicBuckets off");
  return gaps;
}

export const accountPublicAccessBlock: CheckRule = {
  id: "s3.account-public-access-block",
  version: 1,
  title: "Account-level S3 Block Public Access is not fully enabled",
  severity: "high",
  kind: "s3-account-pab",
  resourceTypes: [ACCOUNT],
  requires: ["iam:account-summary"],
  controls: [
    { framework: "fsbp", id: "S3.1" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Turn on all four Block Public Access settings at the account level. Any bucket that genuinely must be public should be the documented exception, served through CloudFront.",
    cli: "aws s3control put-public-access-block --account-id <acct> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
  },
  check: (node) => {
    if (!("s3PublicAccessBlock" in node.attributes)) return { status: "not-applicable" };
    const gaps = pabGaps(node.attributes["s3PublicAccessBlock"] as Pab | null);
    return gaps.length ? { status: "fail", detail: gaps.join("; ") } : { status: "pass" };
  },
};

export const bucketPublicAccessBlock: CheckRule = {
  id: "s3.bucket-public-access-block",
  version: 1,
  title: "Bucket Block Public Access is not fully enabled",
  severity: "high",
  kind: "s3-bucket-pab",
  resourceTypes: [BUCKET],
  requires: ["s3:bucket"],
  controls: [
    { framework: "fsbp", id: "S3.8" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Enable all four Block Public Access settings on the bucket.",
    cli: "aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    terraform: 'resource "aws_s3_bucket_public_access_block" "this" {\n  bucket                  = aws_s3_bucket.this.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}',
  },
  check: (node) => {
    const gaps = pabGaps(node.attributes["publicAccessBlock"] as Pab | undefined);
    return gaps.length ? { status: "fail", detail: gaps.join("; ") } : { status: "pass" };
  },
};

export const bucketPublicPolicy: CheckRule = {
  id: "s3.bucket-public-policy",
  version: 1,
  title: "Bucket policy grants public access",
  severity: "critical",
  kind: "s3-public-policy",
  resourceTypes: [BUCKET],
  requires: ["s3:bucket"],
  controls: [
    { framework: "fsbp", id: "S3.2" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Remove the public statement from the bucket policy (or the whole policy) and enable Block Public Access. If the content must be public, serve it through CloudFront with an origin access control.",
    cli: "aws s3api delete-bucket-policy --bucket <name>",
  },
  check: (node) => {
    if (!("policyIsPublic" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["policyIsPublic"] === true
      ? { status: "fail", detail: "AWS reports the bucket policy as public (GetBucketPolicyStatus)" }
      : { status: "pass" };
  },
};

export const bucketRequireTls: CheckRule = {
  id: "s3.bucket-require-tls",
  version: 1,
  title: "Bucket does not require TLS (aws:SecureTransport)",
  severity: "medium",
  kind: "s3-no-tls-policy",
  resourceTypes: [BUCKET],
  requires: ["s3:bucket"],
  controls: [
    { framework: "fsbp", id: "S3.5" },
    { framework: "nist-csf-2", id: "PR.DS-02" },
  ],
  remediation: {
    text: "Add a bucket policy statement that denies s3:* to all principals when aws:SecureTransport is false.",
    terraform: 'statement {\n  effect    = "Deny"\n  actions   = ["s3:*"]\n  resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]\n  principals { type = "*"  identifiers = ["*"] }\n  condition { test = "Bool"  variable = "aws:SecureTransport"  values = ["false"] }\n}',
  },
  check: (node) => {
    const stmts = node.attributes["policyStatements"];
    if (!Array.isArray(stmts)) return { status: "not-applicable" };
    const ok = (stmts as Array<{ effect: string; conditionKeys?: string[]; actions?: string[] }>).some(
      (s) => s.effect === "Deny" && (s.conditionKeys ?? []).includes("aws:SecureTransport") && (s.actions ?? []).some((a) => a === "s3:*" || a === "*"),
    );
    return ok ? { status: "pass" } : { status: "fail", detail: "no Deny statement conditioned on aws:SecureTransport=false" };
  },
};

export const bucketLogging: CheckRule = {
  id: "s3.bucket-server-access-logging",
  version: 1,
  title: "Bucket has no server access logging",
  severity: "low",
  kind: "s3-no-logging",
  resourceTypes: [BUCKET],
  requires: ["s3:bucket"],
  controls: [
    { framework: "fsbp", id: "S3.9" },
    { framework: "nist-csf-2", id: "DE.CM-09" },
  ],
  remediation: {
    text: "Enable server access logging to a dedicated log bucket, or rely on CloudTrail data events for the bucket if you already pay for them.",
    cli: "aws s3api put-bucket-logging --bucket <name> --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"<name>/\"}}'",
  },
  check: (node) => {
    if (!("loggingEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["loggingEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "server access logging disabled" };
  },
};

export const s3Rules: CheckRule[] = [accountPublicAccessBlock, bucketPublicAccessBlock, bucketPublicPolicy, bucketRequireTls, bucketLogging];
