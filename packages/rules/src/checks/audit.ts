import type { CheckRule } from "../types.js";

const TRAIL = "aws::cloudtrail::trail";

export const cloudTrailMultiRegion: CheckRule = {
  id: "cloudtrail.multi-region-trail",
  version: 1,
  title: "No logging multi-region CloudTrail trail with management events",
  severity: "high",
  kind: "cloudtrail-missing",
  resourceTypes: ["aws::account"],
  requires: ["cloudtrail:trail"],
  controls: [
    { framework: "fsbp", id: "CloudTrail.1" },
    { framework: "nist-csf-2", id: "DE.CM-09" },
  ],
  remediation: {
    text: "Create one multi-region trail (or an organization trail) that records read and write management events, and keep it logging.",
    cli: "aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> --is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name org-trail",
  },
  check: (node) => {
    if (!("cloudTrailMultiRegionLogging" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["cloudTrailMultiRegionLogging"] === true
      ? { status: "pass" }
      : { status: "fail", detail: "no trail is multi-region, logging, and recording management events" };
  },
};

export const cloudTrailEncrypted: CheckRule = {
  id: "cloudtrail.trail-kms-encrypted",
  version: 1,
  title: "CloudTrail trail is not encrypted with a KMS key",
  severity: "medium",
  kind: "cloudtrail-no-kms",
  resourceTypes: [TRAIL],
  requires: ["cloudtrail:trail"],
  controls: [
    { framework: "fsbp", id: "CloudTrail.2" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Configure the trail with a customer-managed KMS key whose policy allows CloudTrail to encrypt and your auditors to decrypt.",
    cli: "aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>",
  },
  check: (node) =>
    node.attributes["kmsEncrypted"] === true ? { status: "pass" } : { status: "fail", detail: "trail logs are not KMS-encrypted" },
};

export const cloudTrailValidation: CheckRule = {
  id: "cloudtrail.log-file-validation",
  version: 1,
  title: "CloudTrail log file validation is disabled",
  severity: "low",
  kind: "cloudtrail-no-validation",
  resourceTypes: [TRAIL],
  requires: ["cloudtrail:trail"],
  controls: [
    { framework: "fsbp", id: "CloudTrail.4" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Enable log file validation so tampering with delivered logs is detectable.",
    cli: "aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
  },
  check: (node) =>
    node.attributes["logFileValidationEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "log file validation off" },
};

export const configRecorder: CheckRule = {
  id: "config.recorder-enabled",
  version: 1,
  title: "AWS Config is not recording in this region",
  severity: "medium",
  kind: "config-off",
  resourceTypes: ["aws::region"],
  requires: ["account:region-settings"],
  controls: [
    { framework: "fsbp", id: "Config.1" },
    { framework: "nist-csf-2", id: "DE.CM-09" },
  ],
  remediation: {
    text: "Enable the AWS Config recorder for all supported resource types (including global resources in one region) with a delivery channel.",
    cli: "aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=<role> --recording-group allSupported=true,includeGlobalResourceTypes=true && aws configservice start-configuration-recorder --configuration-recorder-name default",
  },
  check: (node) => {
    if (!("configRecorderEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["configRecorderEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "no active Config recorder" };
  },
};

export const guardDuty: CheckRule = {
  id: "guardduty.enabled",
  version: 1,
  title: "GuardDuty is not enabled in this region",
  severity: "medium",
  kind: "guardduty-off",
  resourceTypes: ["aws::region"],
  requires: ["account:region-settings"],
  controls: [
    { framework: "fsbp", id: "GuardDuty.1" },
    { framework: "nist-csf-2", id: "DE.CM-01" },
  ],
  remediation: {
    text: "Enable GuardDuty in every region (or delegate it to a security account via Organizations).",
    cli: "aws guardduty create-detector --enable --region <region>",
  },
  check: (node) => {
    if (!("guardDutyEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["guardDutyEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "no enabled GuardDuty detector" };
  },
};

export const lambdaPublicUrl: CheckRule = {
  id: "lambda.function-url-no-auth",
  version: 1,
  title: "Lambda function URL has no authentication",
  severity: "high",
  kind: "lambda-url-no-auth",
  resourceTypes: ["aws::lambda::function"],
  requires: ["lambda:policy"],
  controls: [
    { framework: "fsbp", id: "Lambda.1" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Set the function URL auth type to AWS_IAM, or put the function behind API Gateway with an authorizer. AuthType NONE exposes the function to the internet.",
    cli: "aws lambda update-function-url-config --function-name <fn> --auth-type AWS_IAM",
  },
  check: (node) => {
    const types = node.attributes["urlAuthTypes"];
    if (!Array.isArray(types)) return { status: "not-applicable" };
    return (types as string[]).includes("NONE") ? { status: "fail", detail: "function URL AuthType is NONE" } : { status: "pass" };
  },
};

export const secretRotation: CheckRule = {
  id: "secretsmanager.rotation-enabled",
  version: 1,
  title: "Secrets Manager secret has rotation disabled",
  severity: "low",
  kind: "secret-no-rotation",
  resourceTypes: ["aws::secretsmanager::secret"],
  requires: ["secretsmanager:policy"],
  controls: [
    { framework: "fsbp", id: "SecretsManager.1" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Configure automatic rotation with a rotation Lambda (managed rotation exists for RDS, Redshift, and DocumentDB credentials).",
    cli: "aws secretsmanager rotate-secret --secret-id <arn> --rotation-lambda-arn <fn> --rotation-rules AutomaticallyAfterDays=30",
  },
  check: (node) => {
    if (!("rotationEnabled" in node.attributes)) return { status: "not-applicable" };
    return node.attributes["rotationEnabled"] === true ? { status: "pass" } : { status: "fail", detail: "automatic rotation is not configured" };
  },
};

export const auditRules: CheckRule[] = [cloudTrailMultiRegion, cloudTrailEncrypted, cloudTrailValidation, configRecorder, guardDuty, lambdaPublicUrl, secretRotation];
