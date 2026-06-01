/**
 * Minimal ARN parsing. AWS ARNs look like:
 *   arn:partition:service:region:account-id:resource
 * Region and account-id can be empty for global services (e.g. IAM).
 */
export interface ParsedArn {
  partition: string;
  service: string;
  region: string;
  account: string;
  resource: string;
}

export function parseArn(arn: string): ParsedArn | undefined {
  if (!arn.startsWith("arn:")) return undefined;
  const parts = arn.split(":");
  // arn : partition : service : region : account : resource(may contain ':')
  if (parts.length < 6) return undefined;
  return {
    partition: parts[1] ?? "",
    service: parts[2] ?? "",
    region: parts[3] ?? "",
    account: parts[4] ?? "",
    resource: parts.slice(5).join(":"),
  };
}
