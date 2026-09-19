# CLAUDE.md

Guidance for Claude Code when working in this repo.

## Tool usage discipline

- **Never batch a `Write`/`Edit` in the same parallel tool block as a `Bash`
  call.** When any one call in a parallel block errors, the harness cancels all
  its siblings — so a failing Bash probe silently throws away queued file
  writes. Run file edits and shell commands in separate, sequential steps.
- **Keep Bash commands single-purpose.** Do not chain many actions with
  `&&`/`;` into one mega-command. If an early link fails, the whole thing aborts
  and the output is hard to attribute. One command, one job.
- Don't bundle a "probe" (version check, existence test) with real work in the
  same command. Probe first, read the result, then act.

## Toolchain

- Node is **v22** (verified 2026-09-19; was v20 earlier). npm only by default. pnpm is **not** global and
  corepack can't symlink into `/usr/bin`. pnpm 9.15.0 lives in `~/.local/bin`
  (installed via `corepack enable --install-directory ~/.local/bin pnpm`).
  Prefix shell calls that use pnpm with `export PATH="$HOME/.local/bin:$PATH"`.
- Shell env (including `cd` and exports) does **not** persist between Bash tool
  calls. Use absolute paths; re-export PATH each call.
- `@kumomiru/graph` must be **built** (`dist/`) before packages that depend on
  it typecheck/build, since they resolve it via published `dist` types. Build in
  dependency order: graph → adapters → aws → db → worker / server → viewer
  (`pnpm -r build` does this).
- `noUnusedLocals`/`noUnusedParameters` are effectively on (strict) — keep
  locals used or prefix intentionally-unused params with `_`.

## Project

kumomiru — public cloud environment mapper/visualizer. See `DESIGN.md` for the
full design. pnpm monorepo under `packages/`:

- `@kumomiru/graph` — the normalized graph spine (Zod schema = source of truth;
  types via `z.infer`).
- `@kumomiru/adapters` — ingestion adapters (terraform-state first).
- `@kumomiru/aws` — the only place the AWS SDK is used; the least-privilege
  policy is generated from the actions declared there (`pnpm policy:gen`).
- `@kumomiru/db` — SQLite behind a repository interface (accounts, scans,
  snapshots). `:memory:` in tests.
- `@kumomiru/worker` — scheduler + scan job; assumes a per-account role from
  the host identity. Never holds a long-lived key.
- `@kumomiru/server` — Fastify API; never persists credentials. Shares the
  SQLite file with the worker via `KUMOMIRU_DB_PATH`.
- `docs/cspm-roadmap.md` — the CSPM conversion plan; Phase 0 and 1 are done.
