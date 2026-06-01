# @kumomiru/server

Self-hosted Fastify API that turns ingestion sources into a normalized
[`@kumomiru/graph`](../graph). The app (`app.ts`) is built separately from the
listener (`server.ts`) so tests drive it via `app.inject()` without binding a
port.

## Credential discipline

The server **never persists request bodies or credentials.** The Terraform path
carries no credentials at all; when the live-API path lands, its credentials
will live only for the duration of one request handler and be dropped on return.
Logging redaction is configured up front (`redact.ts`) so secrets never reach the
logs.

## Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness check. |
| GET | `/sample` | The hand-authored sample graph — zero-setup data source for the viewer. |
| POST | `/map/terraform` | Body = parsed `.tfstate` JSON → normalized `Graph`. `400` on invalid state, `422` if the built graph fails referential integrity. |

## Run

```sh
pnpm --filter @kumomiru/server dev     # tsx watch
pnpm --filter @kumomiru/server build
pnpm --filter @kumomiru/server start    # PORT / HOST env (default 127.0.0.1:4000)
```

## Test

```sh
pnpm --filter @kumomiru/server test
```
