import type { AwsCredentials, DiscoveryClient } from "@kumomiru/adapters";

/**
 * A tiny fake account. Region-aware so a multi-region scan yields distinct
 * resources per region; optionally fails a named region to exercise `partial`.
 */
export function fakeClientFactory(opts: { failRegion?: string } = {}) {
  const calls: AwsCredentials[] = [];
  const factory = (creds: AwsCredentials): DiscoveryClient => {
    calls.push({ ...creds });
    const region = creds.region;
    const acct = "123456789012";
    const fail = async (): Promise<never> => {
      throw new Error(`ThrottlingException: ${region}`);
    };
    const failing = opts.failRegion === region;
    return {
      accountId: async () => acct,
      region: () => region,
      vpcs: failing ? fail : async () => [{ vpcId: `vpc-${region}`, tags: { Name: `vpc-${region}` } }],
      subnets: async () => [{ subnetId: `subnet-${region}`, vpcId: `vpc-${region}`, tags: {} }],
      internetGateways: async () => [],
      securityGroups: async () => [
        {
          groupId: `sg-${region}`,
          vpcId: `vpc-${region}`,
          ingress: [{ fromPort: 22, toPort: 22, ipProtocol: "tcp", cidrs: ["0.0.0.0/0"] }],
          tags: {},
        },
      ],
      instances: async () => [
        {
          instanceId: `i-${region}`,
          subnetId: `subnet-${region}`,
          securityGroupIds: [`sg-${region}`],
          tags: {},
        },
      ],
      dbInstances: async () => [],
      functions: async () => [],
      secrets: async () => [],
      roles: async () => [
        {
          roleName: "Admin",
          arn: `arn:aws:iam::${acct}:role/Admin`,
          trustedPrincipals: [{ type: "aws", value: "arn:aws:iam::999988887777:root" }],
          tags: {},
        },
      ],
    };
  };
  return { factory, calls };
}
