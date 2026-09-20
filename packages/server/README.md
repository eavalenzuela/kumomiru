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
| POST | `/map/live` | Body = `{ accessKeyId, secretAccessKey, sessionToken?, region }` → live read-only AWS discovery → `Graph`. Credentials are used in-memory for one run and scrubbed. `400` invalid body, `422` integrity, `502` discovery failure. **Ad-hoc only** (with `/map/terraform`): off when `KUMOMIRU_ADHOC_INGEST=0` or `NODE_ENV=production`. |
| GET | `/accounts` | Registered accounts with latest snapshot, active scan, last scan. |
| POST | `/accounts` | Register or update an account: `{ id, name, roleArn, externalId?, regions?, scheduleCron?, status? }`. `201` new, `200` updated, `400` invalid. |
| GET / DELETE | `/accounts/:id` | One account (with latest snapshot); delete cascades scans and snapshots. |
| GET | `/accounts/:id/latest` | The most recent stored map. `?redacted=1` strips values. `404 no_snapshot` until a scan completes. |
| POST | `/accounts/:id/scans` | Queue a scan for the worker: `{ trigger: "manual" \| "verify" }`. `202`; idempotent while one is queued or running. |
| GET | `/accounts/:id/scans`, `/accounts/:id/snapshots` | History. |
| GET | `/scans/:id`, `/snapshots/:id`, `/snapshots/:id/graph` | Individual records; the graph route honors `?redacted=1`. |
| GET | `/policy/least-privilege` | The generated read-only policy for the scan role. |
| GET | `/findings` | Lifecycle findings. Filters: `accountId`, `status` (open/resolved/suppressed), `severity`, `ruleId`, `source` (native/securityhub/accessanalyzer), `framework`+`control`, `limit`. Most severe first. |
| GET | `/findings/summary?accountId=` | Open counts by severity. |
| GET | `/findings/:id` | One finding with first/last seen, resolved/suppressed state. |
| GET / POST | `/suppressions` | Active suppressions (`?all=1` for revoked/expired too). POST `{ ruleId, resourcePattern, accountId?, reason, expiresAt? }` — applies to open findings immediately. |
| DELETE | `/suppressions/:id` | Revoke; matching findings reopen immediately. |
| GET | `/rules`, `/controls?framework=` | The rule registry (severity, controls, remediation) and framework catalogues. |
| GET | `/compliance?framework=fsbp\|nist-csf-2&accountId=` | Per-control pass/fail/not-assessed from each account's latest snapshot, overall and per account. |
| GET | `/snapshots/:id/diff` | What changed versus the previous snapshot. |

The account routes exist only when the server is started with a database
(`KUMOMIRU_DB_PATH`, shared with the worker). Without one it is the stateless
ad-hoc mapper it was before Phase 1.

The live route's discovery client is injectable (`buildApp({ discoveryClientFactory })`)
so it can be tested with a fake — no AWS or credentials needed. The real
SDK-backed client (`src/aws/sdkClient.ts`) is the only place the AWS SDK is used,
and every call is read-only.

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
