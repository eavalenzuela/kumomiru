import { marker, plaintextSecretFinding, scanRecord } from "../../common/sanitize.js";
import type { CollectContext } from "../collect.js";

/** Lambda functions: env vars (scanned), resource policy, function URLs. */
export async function collectServerless(ctx: CollectContext): Promise<void> {
  const { client, account, region, arn, regionId, nodes, findings } = ctx;
  for (const fn of await client.functions()) {
    const id = arn.fn(account, region, fn.functionName);
    const attributes: Record<string, unknown> = {
      ...(fn.runtime ? { runtime: fn.runtime } : {}),
      ...(fn.urlAuthTypes ? { urlAuthTypes: fn.urlAuthTypes } : {}),
      ...(fn.resourcePolicy ? { hasResourcePolicy: fn.resourcePolicy.length > 0 } : {}),
    };
    const res = scanRecord(fn.environment);
    if (res.found) {
      attributes["environmentSecret"] = marker(res.kinds[0] ?? "secret");
      findings.push(plaintextSecretFinding(id, "Lambda environment variables", res.kinds));
    }
    nodes.push({
      id,
      type: "aws::lambda::function",
      name: fn.functionName,
      account,
      region,
      parent: regionId,
      tags: fn.tags,
      attributes,
    });
    ctx.df.lambdas.push({ id, env: fn.environment });
    if (fn.resourcePolicy) {
      ctx.resources.push({
        id,
        type: "aws::lambda::function",
        account,
        statements: fn.resourcePolicy,
        actions: ["lambda:InvokeFunction", "lambda:InvokeFunctionUrl", "lambda:*"],
      });
    }
  }
}
