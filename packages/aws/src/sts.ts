import {
  STSClient,
  AssumeRoleCommand,
  GetCallerIdentityCommand,
} from "@aws-sdk/client-sts";
import type { AwsCredentials } from "@kumomiru/adapters";

/**
 * Host-identity credential path (docs/cspm-roadmap.md, "Scan credentials").
 *
 * The worker never holds a long-lived key. It inherits whatever identity the
 * host provides — an EC2 instance profile, an EKS IRSA service account, an
 * ECS task role, or a developer's `AWS_PROFILE` — via the SDK's default
 * provider chain, and uses that only to call `sts:AssumeRole` on the
 * per-account scan role. The temporary credentials it gets back live for one
 * scan and are scrubbed by the `CredentialBroker` afterwards.
 */

export interface AssumeScanRoleInput {
  roleArn: string;
  /** Required by the scan-role trust policy; mitigates confused-deputy. */
  externalId?: string;
  /** Region for the STS endpoint and the first regional client. */
  region: string;
  sessionName?: string;
  /** Seconds; STS caps this at the role's MaxSessionDuration. */
  durationSeconds?: number;
}

export interface StsApi {
  assumeRole(input: AssumeScanRoleInput): Promise<AwsCredentials>;
  hostIdentity(region: string): Promise<{ account: string; arn: string }>;
}

/** Real STS calls via the SDK default credential provider chain. */
export const sts: StsApi = {
  async assumeRole(input) {
    const client = new STSClient({ region: input.region });
    const res = await client.send(
      new AssumeRoleCommand({
        RoleArn: input.roleArn,
        RoleSessionName: input.sessionName ?? "kumomiru-scan",
        DurationSeconds: input.durationSeconds ?? 3600,
        ...(input.externalId ? { ExternalId: input.externalId } : {}),
      }),
    );
    const c = res.Credentials;
    if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) {
      throw new Error("AssumeRole returned no credentials");
    }
    return {
      accessKeyId: c.AccessKeyId,
      secretAccessKey: c.SecretAccessKey,
      sessionToken: c.SessionToken,
      region: input.region,
    };
  },

  async hostIdentity(region) {
    const client = new STSClient({ region });
    const res = await client.send(new GetCallerIdentityCommand({}));
    return { account: res.Account ?? "unknown", arn: res.Arn ?? "unknown" };
  },
};
