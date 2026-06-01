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

### Develop

```sh
pnpm --filter @kumomiru/adapters typecheck
pnpm --filter @kumomiru/adapters test
```
