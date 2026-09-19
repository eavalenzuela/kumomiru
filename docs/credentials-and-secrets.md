# Credentials & secrets

kumomiru distinguishes two completely separate concerns. Conflating them is the
usual mistake; keeping them apart is a design pillar.

## A. The credential we *consume* to scan

When you use live discovery (`POST /map/live`), you hand kumomiru read-only AWS
credentials. They are:

- **In-memory only, for exactly one run.** The `CredentialBroker`
  (`packages/adapters/src/aws-live/credentials.ts`) lends the credentials to the
  discovery callback and **scrubs them in a `finally` block** — overwriting the
  secret fields and dropping the reference — whether the run succeeds or fails.
  A spent broker refuses reuse.
- **Never persisted.** No disk, no database. The server holds no reference once
  the request handler returns.
- **Never logged.** Fastify logging redaction (`packages/server/src/redact.ts`)
  censors credential headers and body fields.

### Scheduled scans never take a key at all

The worker (`@kumomiru/worker`) scans registered accounts on a schedule. It
holds no credential of its own: it uses the **host identity** — an EC2
instance profile, an EKS IRSA service account, an ECS task role, or a local
`AWS_PROFILE` — only to call `sts:AssumeRole` on a `KumomiruScanRole` in each
target account, with an ExternalId. The temporary credentials it gets back are
borrowed per discovery pass through the same `CredentialBroker`, scrubbed after
each pass, and the master copy is scrubbed when the scan ends. Nothing about
them is written to the database; only the resulting graph is.

- Host identity needs [`worker-host-policy.json`](./worker-host-policy.json).
- Each scan role needs [`scan-role-trust-policy.json`](./scan-role-trust-policy.json)
  as its trust policy and [`least-privilege-policy.json`](./least-privilege-policy.json)
  as its permissions.
- The pasted-credential path (`POST /map/live`) remains for local, one-off use
  and is disabled by `KUMOMIRU_ADHOC_INGEST=0` or `NODE_ENV=production`.

### Prefer short-lived STS credentials

Supply a `sessionToken` (STS / assume-role). A leaked memory dump of a temporary
session expires in hours; a long-lived access key does not. The server logs a
warning when long-lived keys are used.

### Least-privilege policy

Discovery only ever calls the read-only APIs in
[`least-privilege-policy.json`](./least-privilege-policy.json). That file is
**generated** from the actions the SDK client declares (`pnpm policy:gen`), and
a test fails if it drifts. Attach that policy (or assume a role bearing it) and
kumomiru **cannot** mutate anything — and, critically, **cannot read secret
values**: `secretsmanager:GetSecretValue` and `ssm:GetParameter` are
deliberately absent, and a denylist test also forbids `kms:Decrypt`,
`s3:GetObject`, and `lambda:GetFunction` ("no data-plane reads"). "It cannot
read your secrets" is enforced by the permission set, not a promise.

## B. Secrets we *discover* in your environment

Even with the operator's key discarded, discovery encounters secret material
embedded in resources: EC2 user-data, Lambda environment variables, tags, and
Secrets Manager / SSM SecureString parameters.

kumomiru's rules:

- **Secrets Manager / SSM secrets are listed as nodes but never resolved.** We
  record the ARN and metadata with `{ secretPresent: true, valueResolved: false }`
  and never call `GetSecretValue`.
- **Free-form text is sanitized at the adapter→graph boundary.** The sanitization
  layer (`packages/adapters/src/common/sanitize.ts`) scans user-data and env vars
  for likely secrets (AWS keys, private keys, `password=`/`token=` assignments),
  replaces any match with a `{ secretPresent: true, kind }` marker, and raises a
  `plaintext-secret` **finding**. The raw value never enters the graph.

This turns a risk into a feature: "plaintext secret detected in EC2 user-data"
becomes a surfaced security finding.

> The graph itself is sensitive (it maps your topology and exposure). Self-hosted
> keeps it on your infra; treat exported `.json` maps as confidential.
