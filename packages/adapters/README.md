# @kumomiru/adapters

Ingestion adapters that normalize cloud sources into the shared
[`@kumomiru/graph`](../graph) model. Every adapter implements the same contract
(`Adapter<TInput>`): a pure, side-effect-free `toGraph(input)`. Adapters never
read credentials from globals/env — credential-bearing ones (later) receive a
provider, so the same code can run server-side or as a local CLI agent.

## Terraform-state adapter

The zero-credentials path: input is parsed `.tfstate` JSON (format v4).

- **Nodes** — maps managed resources (VPC, subnet, IGW, instance, security
  group, RDS, Lambda, DynamoDB, Secrets Manager secret, IAM role); skips `data`
  sources. Account/region container nodes are synthesized and deduped from ARNs.
- **Containment** — resolves resource-based parents (`subnet_id`, `vpc_id`)
  through a raw-id index, building `account → region → VPC → subnet → resource`;
  global resources (IAM) parent to the account.
- **Network edges** (first pass) — IGW attachment, security-group membership.
- **Secrets** — Secrets Manager secrets are listed as nodes but values are never
  resolved (`{ secretPresent: true, valueResolved: false }`).

```ts
import { terraformAdapter } from "@kumomiru/adapters";
const graph = terraformAdapter.toGraph(JSON.parse(tfstateJson));
```

## Live AWS adapter

Live read-only discovery, with credentials handled in-memory for one run.

- **Credential broker** (`aws-live/credentials.ts`) — borrows credentials for a
  single run via `use(fn)` and scrubs them in a `finally` block; a spent broker
  refuses reuse. Prefers short-lived STS sessions (`sessionToken`).
- **`DiscoveryClient`** (`aws-live/client.ts`) — a narrow, read-only interface
  describing exactly the data discovery needs. The graph-building logic depends
  only on this, so it is unit-testable with a fake and the AWS SDK is **not** a
  dependency of this package (the server provides the SDK-backed implementation).
- **`discoverGraph(client)`** (`aws-live/discover.ts`) — normalizes the
  discovered resources into a `Graph`: containment, network edges (IGW, SG
  membership, internet-facing ingress), and the assume-role IAM graph
  (external/other-account trust raises a critical finding).
- **Sanitization layer** (`common/sanitize.ts`) — scans user-data / env vars for
  secret material, redacts to `{ secretPresent, kind }` markers, raises
  `plaintext-secret` findings. Secrets Manager secrets are listed, never resolved.

```ts
import { runLiveDiscovery } from "@kumomiru/adapters";
// makeClient: an SDK-backed DiscoveryClient factory (provided by the server).
const graph = await runLiveDiscovery(creds, makeClient); // creds scrubbed after
```

See [`docs/credentials-and-secrets.md`](../../docs/credentials-and-secrets.md)
and [`docs/least-privilege-policy.json`](../../docs/least-privilege-policy.json).

### Develop

```sh
pnpm --filter @kumomiru/adapters typecheck
pnpm --filter @kumomiru/adapters test
```
