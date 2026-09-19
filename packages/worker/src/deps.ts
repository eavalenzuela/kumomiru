import type { AwsCredentials, DiscoveryClientFactory } from "@kumomiru/adapters";
import type { StsApi } from "@kumomiru/aws";
import type { RuleRegistry } from "@kumomiru/rules";

/**
 * Everything the scan job needs from the outside world, injectable so the job
 * is unit-testable with no AWS at all.
 */
export interface WorkerDeps {
  sts: StsApi;
  listRegions: (creds: AwsCredentials) => Promise<string[]>;
  makeClient: DiscoveryClientFactory;
  now: () => Date;
  workerId: string;
  /** Region used for STS and the global (IAM) pass. */
  stsRegion: string;
  /** Rule registry to evaluate; defaults to every built-in rule. */
  registry?: RuleRegistry;
  /** Capabilities the discovery collected; defaults to DISCOVERY_CAPABILITIES. */
  capabilities?: readonly string[];
}
