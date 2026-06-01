import type { Graph } from "@kumomiru/graph";
import { CredentialBroker, type AwsCredentials } from "./credentials.js";
import { discoverGraph } from "./discover.js";
import type { DiscoveryClient } from "./client.js";

export { CredentialBroker } from "./credentials.js";
export type { AwsCredentials, CredentialMeta } from "./credentials.js";
export { discoverGraph } from "./discover.js";
export type * from "./client.js";

/**
 * Factory that turns borrowed credentials into a live DiscoveryClient. The real
 * implementation (SDK-backed) is injected here so the core adapter package does
 * not hard-depend on the AWS SDK — the server provides the factory. In tests, a
 * fake factory returns a fake client.
 */
export type DiscoveryClientFactory = (
  creds: AwsCredentials,
) => Promise<DiscoveryClient> | DiscoveryClient;

/**
 * Run a full live discovery: borrow credentials for exactly one run via the
 * broker, build the client, produce the graph, then the broker scrubs the
 * credentials. Credentials never escape this call.
 */
export async function runLiveDiscovery(
  creds: AwsCredentials,
  makeClient: DiscoveryClientFactory,
): Promise<Graph> {
  const broker = new CredentialBroker(creds);
  return broker.use(async (borrowed) => {
    const client = await makeClient(borrowed);
    return discoverGraph(client);
  });
}
