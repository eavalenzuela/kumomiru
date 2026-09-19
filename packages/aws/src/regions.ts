import { EC2Client, DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import type { AwsCredentials } from "@kumomiru/adapters";

/** IAM actions this module calls; folded into the generated policy. */
export const REGION_ACTIONS = ["ec2:DescribeRegions"] as const;

/**
 * Regions a scheduled scan should cover: every region that is enabled for the
 * account (opt-in regions only when opted in). Sorted for stable scan order.
 */
export async function listEnabledRegions(
  creds: AwsCredentials,
): Promise<string[]> {
  const ec2 = new EC2Client({
    region: creds.region,
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      ...(creds.sessionToken ? { sessionToken: creds.sessionToken } : {}),
    },
  });
  const res = await ec2.send(
    new DescribeRegionsCommand({
      Filters: [
        { Name: "opt-in-status", Values: ["opt-in-not-required", "opted-in"] },
      ],
    }),
  );
  return (res.Regions ?? [])
    .map((r) => r.RegionName ?? "")
    .filter(Boolean)
    .sort();
}
