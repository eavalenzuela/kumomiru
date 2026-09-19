import type { CheckRule, RuleContext } from "../types.js";

const USER = "aws::iam::user";
const ACCOUNT = "aws::account";
const DAY = 86_400_000;

function daysSince(iso: unknown, ctx: RuleContext): number | undefined {
  if (typeof iso !== "string") return undefined;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return undefined;
  return Math.floor((Date.parse(ctx.graph.meta.generatedAt) - t) / DAY);
}

export const rootAccessKeys: CheckRule = {
  id: "iam.root-access-keys",
  version: 1,
  title: "Root user has active access keys",
  severity: "critical",
  kind: "root-access-keys",
  resourceTypes: [ACCOUNT],
  requires: ["iam:account-summary"],
  controls: [
    { framework: "fsbp", id: "IAM.4" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Delete the root user's access keys. Root should only ever sign in interactively with MFA for the handful of tasks that require it; everything else uses IAM roles.",
    cli: "aws iam delete-access-key --access-key-id <AKIA...>   # as root, in the console or CloudShell",
  },
  check: (node) =>
    node.attributes["rootAccessKeysPresent"] === true
      ? { status: "fail", detail: "root access keys exist" }
      : node.attributes["rootAccessKeysPresent"] === false
        ? { status: "pass" }
        : { status: "not-applicable" },
};

export const rootMfa: CheckRule = {
  id: "iam.root-mfa",
  version: 1,
  title: "Root user has no MFA",
  severity: "critical",
  kind: "root-no-mfa",
  resourceTypes: [ACCOUNT],
  requires: ["iam:account-summary"],
  controls: [
    { framework: "fsbp", id: "IAM.9" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Enable MFA for the root user (a hardware key is preferred; FSBP IAM.6 requires hardware MFA). Store the device with the root credentials under dual control.",
  },
  check: (node) =>
    node.attributes["rootMfaEnabled"] === false
      ? { status: "fail", detail: "root MFA is not enabled" }
      : node.attributes["rootMfaEnabled"] === true
        ? { status: "pass" }
        : { status: "not-applicable" },
};

export const passwordPolicy: CheckRule = {
  id: "iam.password-policy",
  version: 1,
  title: "Account password policy is weak or missing",
  severity: "medium",
  kind: "weak-password-policy",
  resourceTypes: [ACCOUNT],
  requires: ["iam:account-summary"],
  controls: [
    { framework: "fsbp", id: "IAM.7" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Set a password policy requiring at least 14 characters with upper, lower, number and symbol classes, and prevent reuse of the last 24 passwords.",
    cli: "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24",
  },
  check: (node) => {
    if (!("passwordPolicy" in node.attributes)) return { status: "not-applicable" };
    const p = node.attributes["passwordPolicy"] as
      | { minimumLength: number; requireSymbols: boolean; requireNumbers: boolean; requireUppercase: boolean; requireLowercase: boolean; reusePrevention?: number }
      | null;
    if (!p) return { status: "fail", detail: "no account password policy is set (AWS defaults apply)" };
    const gaps: string[] = [];
    if (p.minimumLength < 14) gaps.push(`minimum length ${p.minimumLength} < 14`);
    if (!p.requireSymbols) gaps.push("symbols not required");
    if (!p.requireNumbers) gaps.push("numbers not required");
    if (!p.requireUppercase) gaps.push("uppercase not required");
    if (!p.requireLowercase) gaps.push("lowercase not required");
    if ((p.reusePrevention ?? 0) < 24) gaps.push(`reuse prevention ${p.reusePrevention ?? 0} < 24`);
    return gaps.length ? { status: "fail", detail: gaps.join("; "), evidence: { policy: p } } : { status: "pass" };
  },
};

export const userConsoleMfa: CheckRule = {
  id: "iam.user-console-mfa",
  version: 1,
  title: "IAM user with console password has no MFA",
  severity: "high",
  kind: "user-no-mfa",
  resourceTypes: [USER],
  requires: ["iam:credential-report"],
  controls: [
    { framework: "fsbp", id: "IAM.5" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Require MFA for every user with a console password, or better, move human access to IAM Identity Center and delete the console password.",
    cli: "aws iam enable-mfa-device --user-name <user> --serial-number <arn> --authentication-code1 <c1> --authentication-code2 <c2>",
  },
  check: (node) => {
    if (!("passwordEnabled" in node.attributes)) return { status: "not-applicable" };
    if (node.attributes["passwordEnabled"] !== true) return { status: "not-applicable" };
    return node.attributes["mfaActive"] === true ? { status: "pass" } : { status: "fail", detail: "console password enabled without MFA" };
  },
};

export const accessKeyRotation: CheckRule = {
  id: "iam.access-key-rotation",
  version: 1,
  title: "IAM user access key older than 90 days",
  severity: "medium",
  kind: "stale-access-key",
  resourceTypes: [USER],
  requires: ["iam:credential-report"],
  controls: [
    { framework: "fsbp", id: "IAM.3" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Rotate the access key (create a new one, switch the consumer, deactivate then delete the old one). Prefer short-lived credentials via roles so there is no key to rotate.",
    cli: "aws iam create-access-key --user-name <user>   # then update-access-key --status Inactive on the old one, then delete-access-key",
  },
  check: (node, ctx) => {
    if (!("accessKey1Active" in node.attributes)) return { status: "not-applicable" };
    const stale: string[] = [];
    for (const n of [1, 2] as const) {
      if (node.attributes[`accessKey${n}Active`] !== true) continue;
      const age = daysSince(node.attributes[`accessKey${n}LastRotated`], ctx);
      if (age !== undefined && age > 90) stale.push(`key ${n} is ${age} days old`);
    }
    if (stale.length) return { status: "fail", detail: stale.join("; ") };
    return node.attributes["accessKey1Active"] === true || node.attributes["accessKey2Active"] === true
      ? { status: "pass" }
      : { status: "not-applicable" };
  },
};

export const unusedCredentials: CheckRule = {
  id: "iam.unused-credentials",
  version: 1,
  title: "IAM user credentials unused for 90 days",
  severity: "medium",
  kind: "unused-credentials",
  resourceTypes: [USER],
  requires: ["iam:credential-report"],
  controls: [
    { framework: "fsbp", id: "IAM.8" },
    { framework: "nist-csf-2", id: "PR.AA-01" },
  ],
  remediation: {
    text: "Deactivate the unused password or access key; delete it after a grace period. Unused credentials are pure attack surface.",
    cli: "aws iam update-access-key --user-name <user> --access-key-id <id> --status Inactive",
  },
  check: (node, ctx) => {
    if (!("passwordEnabled" in node.attributes)) return { status: "not-applicable" };
    const idle: string[] = [];
    if (node.attributes["passwordEnabled"] === true) {
      const d = daysSince(node.attributes["passwordLastUsed"], ctx);
      if (d !== undefined && d > 90) idle.push(`password unused for ${d} days`);
    }
    for (const n of [1, 2] as const) {
      if (node.attributes[`accessKey${n}Active`] !== true) continue;
      const used = node.attributes[`accessKey${n}LastUsed`];
      const d = daysSince(used ?? node.attributes[`accessKey${n}LastRotated`], ctx);
      if (d !== undefined && d > 90) idle.push(`access key ${n} unused for ${d} days`);
    }
    if (idle.length) return { status: "fail", detail: idle.join("; ") };
    const any = node.attributes["passwordEnabled"] === true || node.attributes["accessKey1Active"] === true || node.attributes["accessKey2Active"] === true;
    return any ? { status: "pass" } : { status: "not-applicable" };
  },
};

export const iamRules: CheckRule[] = [rootAccessKeys, rootMfa, passwordPolicy, userConsoleMfa, accessKeyRotation, unusedCredentials];
