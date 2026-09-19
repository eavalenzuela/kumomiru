# @kumomiru/worker

The scan worker. Runs beside the API server, shares its SQLite file, and is
the only process that talks to AWS on a schedule.

## What it does, per tick

1. Takes the `scheduler` lease (so only one worker enqueues), and for every
   `active` account whose cron schedule is due, enqueues a scan.
2. Claims the oldest queued scan whose account has no running scan and runs it:
   - assume the account's scan role from the **host identity** (instance
     profile, IRSA, ECS task role, or a local `AWS_PROFILE`) with the account's
     ExternalId;
   - one `global` discovery pass (IAM roles/users, assume-role analysis);
   - one `regional` pass per enabled region, each inside a `CredentialBroker`
     that scrubs the borrowed credentials afterwards;
   - merge, check referential integrity, persist the snapshot;
   - a region that fails leaves the scan `partial`, never `failed`.

## Credentials

The worker never stores a key. `docs/worker-host-policy.json` is the only
permission the host identity needs; `docs/scan-role-trust-policy.json` is the
trust policy for the scan role in each target account.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KUMOMIRU_DB_PATH` | `./kumomiru.db` | SQLite file shared with the server. |
| `KUMOMIRU_WORKER_ID` | `<hostname>-<pid>` | Lease holder / scan attribution. |
| `KUMOMIRU_POLL_SECONDS` | `30` | Tick interval. |
| `KUMOMIRU_STS_REGION` | `us-east-1` | Region for STS and the global pass. |

```sh
pnpm --filter @kumomiru/worker dev
```
