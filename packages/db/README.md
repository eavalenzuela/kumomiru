# @kumomiru/db

Persistence behind a repository interface. SQLite (`better-sqlite3`, WAL mode)
is the only implementation today; the interface is deliberately free of
SQLite-specific JSON functions so Postgres can follow without touching callers.

| File | Role |
|---|---|
| `repository.ts` | Record types and the `AccountRepo`, `ScanRepo`, `SnapshotRepo`, `SettingsRepo`, `LeaseRepo` interfaces. |
| `migrations.ts` | Numbered SQL migrations, applied on open via `PRAGMA user_version`. |
| `sqlite.ts` | `openDatabase(path)` → `Database`. Pass `":memory:"` in tests. |

Deployment unit until Postgres lands: one host, one worker, one API server,
one SQLite file on local disk. Only the worker writes `scans` (beyond
enqueueing), `snapshots`; the server writes `accounts`, `settings`.
