# kumomiru

A self-hosted cloud environment mapper and visualizer for AWS, on its way to
becoming a monitoring-only Cloud Security Posture Management tool.

kumomiru discovers your resources with **read-only** credentials, normalizes
them into one graph, and renders that graph as an interactive architecture
diagram with three lenses: **network**, **IAM reachability**, and **data
flow**. Security findings such as plaintext secrets and externally assumable
roles are drawn on the map, on the resource they affect.

It never holds a write permission and never reads a secret value. That is
enforced by the [least-privilege policy](docs/least-privilege-policy.json) it
generates, not by promise.

## Documents

| Document | What it is |
|---|---|
| [`DESIGN.md`](DESIGN.md) | The thesis, the graph model, the three lenses, and the credential and secrets pillars. Start here. |
| [`docs/cspm-roadmap.md`](docs/cspm-roadmap.md) | The plan for converting the mapper into a CSPM: locked decisions and eight dependency-ordered phases. |
| [`docs/credentials-and-secrets.md`](docs/credentials-and-secrets.md) | How scan credentials are handled and how discovered secrets are redacted. |
| [`IMPROVEMENTS.md`](IMPROVEMENTS.md), [`PLANNED_IMPROVEMENTS.md`](PLANNED_IMPROVEMENTS.md) | Two completed improvement passes, kept as a record. |

## Layout

pnpm monorepo under `packages/`:

| Package | Role |
|---|---|
| [`@kumomiru/graph`](packages/graph) | The normalized graph spine. Zod schema is the source of truth. |
| [`@kumomiru/adapters`](packages/adapters) | Ingestion: Terraform state and live AWS discovery, plus the IAM and dataflow analysis passes. |
| [`@kumomiru/aws`](packages/aws) | The only place the AWS SDK is used. The least-privilege policy is generated from the actions declared here. |
| [`@kumomiru/rules`](packages/rules) | Typed posture rules over the graph, FSBP and NIST CSF 2.0 mappings, compliance roll-up. |
| [`@kumomiru/db`](packages/db) | SQLite behind a repository interface: accounts, scans, snapshots, findings lifecycle. |
| [`@kumomiru/worker`](packages/worker) | Scheduled scans. Assumes a read-only role in each account from the host's own identity. Never holds a key. |
| [`@kumomiru/server`](packages/server) | Fastify API. Serves stored snapshots; ad-hoc ingest with pasted credentials is dev-only. |
| [`@kumomiru/viewer`](packages/viewer) | React + Cytoscape.js map with ELK layered layout. |

## Run it

Requirements: Node 22 and pnpm 9.

```sh
pnpm install
pnpm build          # all packages, in dependency order
pnpm dev            # server :4000, worker, and viewer :5173 together
```

Open http://localhost:5173. The viewer loads a built-in sample graph with no
credentials. **Load data** offers a Terraform state upload, a one-off live scan
with pasted credentials (dev only), and the registered accounts.

### Scheduled scans (the real path)

The worker scans registered accounts on a cron schedule. It never stores a
key: it uses the identity of the host it runs on (instance profile, IRSA, ECS
task role, or your `AWS_PROFILE` locally) to assume a read-only role in each
target account.

1. In each target account, create `KumomiruScanRole` with the trust policy in
   [`docs/scan-role-trust-policy.json`](docs/scan-role-trust-policy.json) (fill
   in the worker's role ARN and an ExternalId) and attach the generated
   read-only policy from [`docs/least-privilege-policy.json`](docs/least-privilege-policy.json).
2. Give the worker's host identity [`docs/worker-host-policy.json`](docs/worker-host-policy.json).
3. Register the account and verify the role:

```sh
curl -s -X POST localhost:4000/accounts -H 'content-type: application/json' -d '{
  "id": "123456789012", "name": "prod",
  "roleArn": "arn:aws:iam::123456789012:role/KumomiruScanRole",
  "externalId": "choose-something-unguessable",
  "scheduleCron": "0 */6 * * *"
}'
curl -s -X POST localhost:4000/accounts/123456789012/scans -d '{"trigger":"verify"}' -H 'content-type: application/json'
```

Once verified the account is `active` and scans run on schedule. The latest
map is at `GET /accounts/:id/latest` and in the viewer's Accounts tab. Every
scan also runs the posture rules: findings with lifecycle at `GET /findings`,
the per-control roll-up at `GET /compliance?framework=fsbp`, and what changed
at `GET /snapshots/:id/diff`.

Both processes read the same SQLite file, `KUMOMIRU_DB_PATH` (default
`./kumomiru.db`). Set `KUMOMIRU_ADHOC_INGEST=0` (or `NODE_ENV=production`) to
disable the pasted-credential and Terraform-upload routes.

## Develop

```sh
pnpm test           # 140+ tests across graph, adapters, aws, rules, db, worker, server
pnpm typecheck
pnpm policy:gen     # regenerate docs/least-privilege-policy.json after changing the policy
```

`@kumomiru/graph` must be built before the packages that depend on it will
typecheck, since they resolve it through its `dist` types. `pnpm build` handles
the order.

## License

MIT
