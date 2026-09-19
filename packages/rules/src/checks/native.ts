import type { AdoptRule } from "../types.js";

/**
 * Findings the adapters already raise. Detection stays in
 * `sanitize.ts` / `analysis/iam.ts`; here they get controls, remediation,
 * and — via the rule id — lifecycle. Neither maps cleanly to an FSBP
 * control, so they carry NIST CSF references only.
 */
export const plaintextSecret: AdoptRule = {
  id: "kumomiru.plaintext-secret",
  version: 1,
  adopts: "plaintext-secret",
  title: "Plaintext secret in resource configuration",
  severity: "high",
  kind: "plaintext-secret",
  controls: [
    { framework: "nist-csf-2", id: "PR.AA-01" },
    { framework: "nist-csf-2", id: "PR.DS-01" },
  ],
  remediation: {
    text: "Move the value into Secrets Manager or an SSM SecureString parameter, reference it by ARN, rotate the exposed credential, and redeploy so the plaintext no longer appears in user-data, environment variables, or tags.",
    cli: "aws secretsmanager create-secret --name <name> --secret-string '<value>'   # then reference the ARN",
  },
};

export const externalCanAssume: AdoptRule = {
  id: "kumomiru.external-can-assume",
  version: 1,
  adopts: "external-can-assume",
  title: "Role can be assumed by an external principal",
  severity: "critical",
  kind: "external-can-assume",
  controls: [{ framework: "nist-csf-2", id: "PR.AA-05" }],
  remediation: {
    text: "Confirm the trusted account is intended. If so, require an ExternalId condition and scope the trust to a specific role rather than the account root; if not, remove the principal from the trust policy.",
    cli: "aws iam update-assume-role-policy --role-name <role> --policy-document file://trust.json",
  },
};

export const nativeRules: AdoptRule[] = [plaintextSecret, externalCanAssume];
