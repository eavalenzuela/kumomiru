import type { CollectContext } from "../collect.js";

/** SQS queues and SNS topics, with their resource policies for the access pass. */
export async function collectMessaging(ctx: CollectContext): Promise<void> {
  const { client, account, region, regionId, nodes } = ctx;
  for (const q of (await client.sqsQueues?.()) ?? []) {
    nodes.push({ id: q.arn, type: "aws::sqs::queue", name: q.name, account, region, parent: regionId, tags: q.tags, attributes: { kmsEncrypted: q.kmsEncrypted } });
    if (q.policyStatements) {
      ctx.resources.push({ id: q.arn, type: "aws::sqs::queue", account, statements: q.policyStatements, actions: ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:*"] });
    }
  }
  for (const t of (await client.snsTopics?.()) ?? []) {
    nodes.push({ id: t.arn, type: "aws::sns::topic", name: t.name, account, region, parent: regionId, tags: t.tags, attributes: { kmsEncrypted: t.kmsEncrypted } });
    if (t.policyStatements) {
      ctx.resources.push({ id: t.arn, type: "aws::sns::topic", account, statements: t.policyStatements, actions: ["sns:Publish", "sns:Subscribe", "sns:*"] });
    }
  }
}
