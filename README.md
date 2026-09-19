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
| [`@kumomiru/server`](packages/server) | Fastify API. Credentials live in memory for one request and are scrubbed. |
| [`@kumomiru/viewer`](packages/viewer) | React + Cytoscape.js map with ELK layered layout. |

## Run it

Requirements: Node 22 and pnpm 9.

```sh
pnpm install
pnpm build          # graph → adapters → server → viewer, in dependency order
pnpm dev            # server on :4000 and viewer on :5173 together
```

Open http://localhost:5173. The viewer loads a built-in sample graph with no
credentials. Use **Load data** to upload a Terraform state file or run a live
read-only scan of an AWS account.

For a live scan, attach the generated read-only policy to a role and prefer
short-lived STS credentials:

```sh
curl -sO http://localhost:4000/policy/least-privilege
```

## Develop

```sh
pnpm test           # 70+ tests across graph, adapters, server
pnpm typecheck
pnpm policy:gen     # regenerate docs/least-privilege-policy.json after changing the policy
```

`@kumomiru/graph` must be built before the packages that depend on it will
typecheck, since they resolve it through its `dist` types. `pnpm build` handles
the order.

## License

MIT
