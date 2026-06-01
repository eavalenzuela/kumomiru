# @kumomiru/graph

The normalized cloud graph **spine**. This is the single shared model that every
ingestion adapter (Terraform state, AWS Config, live AWS API) emits and that the
Cytoscape viewer consumes. Everything downstream works only on this model and
never touches a cloud SDK.

## Layout

| File | Role |
|---|---|
| `schema.ts` | **Source of truth** — Zod runtime schemas for `CloudNode`, `CloudEdge`, `Finding`, `Graph`. |
| `types.ts` | Static TypeScript types, **derived** from the schemas via `z.infer` (no drift). |
| `validate.ts` | `parseGraph` / `safeParseGraph` + `checkReferentialIntegrity` (dangling edges, dup ids, bad parents). |
| `sample.ts` | A hand-authored demo graph exercising all three lenses + a redacted secret + findings. |
| `index.ts` | Public barrel. |

## Model

- **Nodes** are resources; containment is expressed with `parent`, which drives
  Cytoscape compound nodes: `account → region → VPC → subnet → resource`.
- **Edges** carry a `lens` (`network` | `iam` | `dataflow`). The viewer's lens
  toggle is just filtering edges by this field over one shared node set.
- **Findings** are surfaced security observations (e.g. `plaintext-secret`,
  `external-can-assume`).
- **Secrets are never resolved** — `attributes` only ever carries markers like
  `{ secretPresent: true }`, never a value.

## Develop

```sh
pnpm --filter @kumomiru/graph typecheck
pnpm --filter @kumomiru/graph build
pnpm --filter @kumomiru/graph test
```
