/**
 * The normalized security-group ingress rule stored on
 * `aws::ec2::security-group` nodes as `attributes.ingress`. Shared by the live
 * and Terraform adapters so the rule engine reads one shape.
 */
export interface IngressRule {
  fromPort?: number;
  toPort?: number;
  /** "tcp" | "udp" | "icmp" | "-1" (all). */
  protocol?: string;
  cidrs: string[];
  sourceGroupIds: string[];
}

export function ingressAttribute(
  rules: ReadonlyArray<{
    fromPort?: number;
    toPort?: number;
    ipProtocol?: string;
    cidrs: string[];
    sourceGroupIds?: string[];
  }>,
): IngressRule[] {
  return rules.map((r) => ({
    ...(r.fromPort !== undefined ? { fromPort: r.fromPort } : {}),
    ...(r.toPort !== undefined ? { toPort: r.toPort } : {}),
    ...(r.ipProtocol !== undefined ? { protocol: r.ipProtocol } : {}),
    cidrs: [...r.cidrs],
    sourceGroupIds: [...(r.sourceGroupIds ?? [])],
  }));
}
