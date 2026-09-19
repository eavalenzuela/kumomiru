import type { AwsCredentials, DiscoveryClientFactory } from "@kumomiru/adapters";
import type { StsApi } from "@kumomiru/aws";

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
}
