# kumomiru → CSPM roadmap

Converting kumomiru from a cloud environment mapper into a monitoring-focused
Cloud Security Posture Management tool. Companion to [`DESIGN.md`](../DESIGN.md),
which remains the authority on the graph spine, the three lenses, and the
credential/secrets pillars. This document covers what changes, in what order,
and what was decided up front.

"Monitoring, not managing": kumomiru observes and reports. It never holds a
cloud write permission and never remediates on your behalf.

---

## 1. Why, and what carries over

The thesis in DESIGN §1 still holds: existing CSPMs are tables of findings with
a map bolted on, if at all. kumomiru inverts that. **A posture finding drawn on
the map of the resource it affects is the product.** The CSPM conversion adds
three things on top of the existing spine, and changes nothing underneath it:

1. **Persisted snapshots** — every scan produces a `Graph` that is stored, so
   there is history to diff.
2. **A rule engine over the `Graph`** — typed checks that yield pass/fail per
   resource per control, mapped to compliance frameworks.
3. **Finding lifecycle** — findings open, persist across scans, resolve when
   they disappear, and can be suppressed with a reason and expiry.

Everything downstream of the graph (viewer, lenses, rules, diff, reports)
continues to work only on the normalized model and never touches a cloud SDK.

### Invariants carried forward

These are load-bearing. Every phase below is constrained by them.

| Invariant | Where it is enforced today | What the CSPM work must preserve |
|---|---|---|
| No mutating cloud calls | [`docs/least-privilege-policy.json`](./least-privilege-policy.json) | Policy becomes *generated* from collector metadata, with a denylist test |
| Never resolve secret values | `secretsmanager:GetSecretValue`, `ssm:GetParameter` absent from policy | **Extended for the CSPM to "no data-plane reads":** the denylist test also forbids `kms:Decrypt`, `s3:GetObject`, `lambda:GetFunction`. One documented exception: an operator-opted-in `s3:GetObject` scoped to a single Terraform state bucket (Phase 8). |
| No stored cloud keys | `CredentialBroker` in `packages/adapters/src/aws-live/credentials.ts` scrubs after one run | Worker assumes a role per run from host identity; broker wraps every run |
| Adapters are pure over `DiscoveryClient` | `packages/adapters/src/aws-live/client.ts` | New collectors add *optional* client methods; fakes still compile |
| IAM is one analysis pass, not an adapter | `analyzeAssumeRole` in `packages/adapters/src/analysis/iam.ts` | Resource-policy analysis joins it in the same module family; no second brain |
| Sanitize at the adapter→graph boundary | `packages/adapters/src/common/sanitize.ts` | Every new free-text field (task-def env, launch-template user-data, ASFF text, uploaded templates) passes through it |
| Redaction is allowlist-based | `redactGraph` in `packages/graph/src/redact.ts` | Every new value-bearing field is added to the allowlist decision explicitly |

---

## 2. Decisions locked for the CSPM conversion

| Area | Decision |
|---|---|
| Storage | **SQLite** via `better-sqlite3`, WAL mode, JSON columns for snapshots. Behind a repository interface so Postgres can follow without touching callers. |
| Scan credentials | **Host identity + assume-role chain.** The worker inherits the identity of where it runs (instance profile, IRSA, ECS task role) and assumes a read-only `KumomiruScanRole` in each target account with an ExternalId. No long-lived key is ever stored. The existing `CredentialBroker` wraps each assumed session for exactly one account/region run. |
| Rule engine | **TypeScript check registry.** Each rule is a typed function over the `Graph`, registered with control ids, severity, and remediation (guidance text plus an AWS CLI or Terraform snippet). No Rego, no DSL. |
| Frameworks | **AWS Foundational Security Best Practices (FSBP)** and **NIST CSF v2**. CIS is not in scope for the first release. |
| Managed feeds | **Ingest Security Hub and IAM Access Analyzer** findings. When either is not enabled in an account, native rules cover the same controls. The fallback is automatic per account and region. |
| Change detection | **Scheduled scans + snapshot diff only.** No EventBridge or AWS Config change stream in this roadmap. |
| Auth | **OIDC SSO** (Okta, Entra, Google). Users table with roles `viewer` and `admin`. |
| Account onboarding | **Both.** AWS Organizations auto-discovery with a generated CloudFormation StackSet for the scan role, and manual account/role registration for standalone accounts. |
| Execution | **Separate `@kumomiru/worker` process** runs the scheduler, discovery, rules, and alerting. The API server stays separate. Both share one SQLite file. |
| UI | **Both map-first and dashboard-first.** Posture, change, and drift render as overlays on the Cytoscape map; a conventional dashboard exists alongside. The operator picks the default home. |
| Multi-cloud | **AWS only.** `provider: z.literal("aws")` stays. Node type namespaces already leave room. |
| Alerting | **Signed generic webhook** (covers Slack, Teams, PagerDuty, SIEMs) and a **Linear** ticket integration via API key. |
| Remediation | **Guidance text + CLI/Terraform snippet** per rule. The operator runs it. |
| Reports | **Compliance status export** per framework and control, as CSV and JSON. |
| IaC drift | **After scanner, rules, and history.** Three inputs through one "declared intent" abstraction: live CloudFormation API (covers CDK-deployed infra via `aws:cloudformation:*` tags and `DetectStackDrift`), uploaded `cdk.out` cloud assemblies or CloudFormation templates, and Terraform state. |

---

## 3. Target architecture

```
                         ┌──────────────── @kumomiru/worker ────────────────┐
  host identity          │ scheduler ─▶ per account:                         │
  (instance profile,     │   STS AssumeRole(KumomiruScanRole, ExternalId)    │
   IRSA, ECS role) ─────▶│   └▶ CredentialBroker (one run, scrubbed after)   │
                         │       └▶ collectors ─▶ sanitize ─▶ Graph          │
                         │            └▶ IAM pass (assume-role + resource)   │
                         │            └▶ managed feeds (SecHub, Access Anlzr)│
                         │            └▶ rules ─▶ diff vs prev ─▶ lifecycle  │
                         │            └▶ alerts (webhook, Linear)            │
                         └──────────────────────┬──────────────────────────┘
                                                ▼
                                   SQLite (WAL) ── @kumomiru/db
                                                ▲
                         ┌──────────────────────┴──────────────────────────┐
                         │ @kumomiru/server (Fastify)                        │
                         │  OIDC auth · accounts · snapshots · findings      │
                         │  compliance · reports · alerts · intent uploads   │
                         └──────────────────────┬──────────────────────────┘
                                                ▼
                         ┌──────────────── @kumomiru/viewer ────────────────┐
                         │  Map (lenses + posture/change/drift overlays)     │
                         │  Dashboard · Findings · Compliance · History      │
                         └───────────────────────────────────────────────────┘
```

### Package layout after the conversion

```
packages/
├── graph/      @kumomiru/graph     spine (unchanged shape) + diff, lifecycle, controls schemas
├── adapters/   @kumomiru/adapters  collectors, analysis passes, feeds, intent (drift)
├── aws/        @kumomiru/aws       NEW — SDK clients, assume-role, region enumeration,
│                                   policy generation. Moves out of server.
├── rules/      @kumomiru/rules     NEW — rule registry, frameworks, compliance roll-up
├── db/         @kumomiru/db        NEW — repository interfaces, SQLite impl, migrations
├── worker/     @kumomiru/worker    NEW — scheduler, scan/feed/drift/alert jobs
├── server/     @kumomiru/server    API, OIDC, no SDK dependency after Phase 1
└── viewer/     @kumomiru/viewer    map + dashboard
```

Build order becomes: graph → aws → adapters → rules → db → worker / server → viewer.

### Deployment unit

Until the Postgres repository lands, the supported deployment is **one host:
one worker, one API server, one SQLite file on local disk**. SQLite over NFS or
across hosts is not supported. Only the worker writes snapshot, resource,
finding, and rule-result tables; the server writes accounts, users, sessions,
suppressions, settings, alert channels, and intent uploads.

---

## 4. Phases

Ordered by dependency. The dependency graph is in §8.

### Phase 0 — Groundwork (done, 2026-09-19)

Small, independent fixes that every later phase builds on, landed before any
new package exists.

- **Clock injection.** `discoverGraph(client, { now })`; live maps no longer
  claim `generatedAt` of 1970.
- **One container-type set.** `CONTAINER_TYPES` / `isContainer` exported from
  `@kumomiru/graph`; adapters and viewer import it instead of each keeping a
  copy.
- **User-data on live scans.** The SDK client now calls
  `DescribeInstanceAttribute` per instance (bounded concurrency, per-instance
  failure tolerated) so the plaintext-secret sanitizer actually runs on live
  EC2 user-data. `ec2:DescribeInstanceAttribute` added to the policy.
- **Partition-aware ARNs.** `DiscoveryClient.partition?()` derived from the
  caller identity; synthesized node ids use it, so GovCloud and China ids
  match what IAM returns.
- **Policy as single source of truth.** `docs/least-privilege-policy.json` is
  generated from `LEAST_PRIVILEGE_POLICY` (`pnpm policy:gen`); a test fails on
  drift, and a denylist test fails if any data-plane read
  (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`,
  `s3:GetObject`, `lambda:GetFunction`) ever appears. Phase 1 replaces the
  hand-maintained action list with per-collector `requiredActions`; the tests
  stay.
- **Housekeeping.** Root `README.md`; root `pnpm dev` runs server and viewer
  together; viewer bundle split into app / cytoscape / elk / react / zod
  chunks (app chunk 2.1 MB → 34 KB).

### Phase 1 — Foundation: persistence, worker, host-identity scanning (done, 2026-09-19)

Landed as designed below, with these deviations worth knowing:

- Build order is graph → adapters → **aws** → db → worker / server → viewer,
  because `@kumomiru/aws` implements the `DiscoveryClient` contract that
  adapters defines (not the other way round as first sketched).
- The policy is assembled from `DISCOVERY_ACTIONS` (client) and
  `REGION_ACTIONS` (regions) constants declared next to the SDK calls, which
  is the "per-collector `requiredActions`" idea in its smallest form.
- `discoverGraph` takes `scope: "all" | "regional" | "global"` rather than a
  boolean; the worker runs one `global` pass and one `regional` pass per region.
- Cron schedules use `croner` (5-field, UTC). Default `0 */6 * * *`.
- A `verify` scan trigger assumes the role, checks it lands in the registered
  account, and flips the account to `active`; no discovery.
- `better-sqlite3` compiled from source on this machine (Node 22). Deployment
  images need build tools or a Node version with a prebuilt binary.
- Region-scoped resource ids (`igw-…`, `sg-…`) are used in edge ids without a
  region prefix; `mergeGraphs` dedupes by id, so a genuine cross-region id
  collision would drop an edge. AWS ids are random enough that this is
  theoretical; Phase 3 should prefix edge ids anyway.


**Goal.** Unattended, scheduled, multi-region scans of registered accounts,
persisted as snapshots. The API server serves stored snapshots instead of
one-shot results.

**Deliverables.**

- `@kumomiru/db` (`packages/db/src/`)
  - `repository.ts` — interfaces: `SnapshotRepo`, `AccountRepo`, `ScanRepo`,
    `FindingRepo`, `UserRepo`, `SuppressionRepo`, `SettingsRepo`. No
    SQLite-specific JSON functions leak through the interface.
  - `sqlite/` — `better-sqlite3` implementation, WAL, `busy_timeout`.
  - `migrations/` — numbered SQL applied on open.
  - `memory.ts` — `:memory:` instance for tests.
- `@kumomiru/aws` (`packages/aws/src/`)
  - `client.ts` — `packages/server/src/aws/sdkClient.ts` moves here unchanged
    in behavior. The server drops all `@aws-sdk/*` dependencies.
  - `sts/assumeRole.ts` — host identity via the SDK default provider chain →
    `AssumeRole` with `ExternalId` → temporary credentials → wrapped in the
    existing `CredentialBroker` for one account/region run.
  - `regions.ts` — `DescribeRegions` filtered to opted-in regions.
  - `collectors/` scaffold. Every collector exports `requiredActions: string[]`.
  - `policy.ts` — assembles the least-privilege policy from collector
    metadata. Replaces the hand-maintained list in
    `packages/server/src/routes/policy.ts`. A test asserts
    `docs/least-privilege-policy.json` equals the generated output. A second
    test asserts the denylist: the policy must never contain
    `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`,
    `s3:GetObject`, `lambda:GetFunction`, or any action outside the Read/List
    access levels. This is the original "cannot read your secrets" guarantee
    widened to "cannot read your data plane". The single permitted exception
    is the Terraform state bucket statement in Phase 8, which is generated
    only when an operator enables it and is scoped to one bucket ARN; the
    denylist test must still fail on any `s3:GetObject` with `Resource: "*"`.
- `@kumomiru/worker` (`packages/worker/src/`)
  - `main.ts`, `scheduler.ts` — per-account interval with jitter, single-flight
    per account, DB-backed lease in `lock.ts` so two workers never double-scan.
  - `jobs/scan.ts` — assume role → one global pass (IAM, account-level) → one
    `discoverGraph` per region → `mergeGraphs` → `checkReferentialIntegrity`
    → persist snapshot. Throttling produces a `partial` scan, never a failed
    one.
- `@kumomiru/adapters`
  - `discoverGraph(client, { clock, global })` — inject the clock; split
    global from regional collection.
  - `common/merge.ts` — `mergeGraphs(graphs[]): Graph`. Dedupes container
    nodes, concatenates the rest, stable ordering.
- `@kumomiru/server`
  - `routes/accounts.ts` — manual registration: account id, role ARN,
    ExternalId, regions, schedule.
  - `routes/scans.ts` — list, trigger.
  - `routes/snapshots.ts` — `GET /snapshots/:id/graph` (honors the existing
    `?redacted=1` via `redactGraph`), `GET /accounts/:id/latest`.
  - `POST /map/live` and `POST /map/terraform` stay, behind
    `KUMOMIRU_ADHOC_INGEST` (default on in dev, off in production). Ad-hoc
    results may be persisted as `source: "adhoc"` snapshots.
- Viewer: the existing `DataSourcePanel` gains an "Accounts" tab that loads
  the latest snapshot. The full UI is Phase 6.
- New docs: `docs/worker-host-policy.json` (`sts:AssumeRole` on
  `arn:*:iam::*:role/KumomiruScanRole`, name configurable) and
  `docs/scan-role-trust-policy.json` (trusts the worker host role ARN with an
  `sts:ExternalId` condition).

**Permissions added to the scan role.** `ec2:DescribeRegions`.
(`ec2:DescribeInstanceAttribute` landed in Phase 0.)

**Schema deltas.** `GraphMeta` gains optional `accountId`, `regions`,
`snapshotId`, `scanId`. The sample graph and viewer are unaffected.

**Exit criterion.** A worker on a host with an instance profile scans two
registered accounts across all opted-in regions on a schedule.
`GET /accounts/:id/latest` returns a graph the viewer renders. `pnpm -r test`
is green with `:memory:` repository tests. The pasted-credential path still
works when the flag is on.

**Parallelism.** Nothing else can start before this. Internally, `db` and
`aws` are independent.

---

### Phase 2 — Rule engine, frameworks, finding lifecycle, snapshot diff (done, 2026-09-19)

Landed as designed below. Deviations and specifics:

- Security-group ingress rules are now stored on the SG node as
  `attributes.ingress` (shared `IngressRule` shape, both adapters) so rules
  can evaluate exposure; `redactGraph` keeps the rule shape but only the two
  "anyone" CIDRs.
- First rule tranche: EC2.13, EC2.14, EC2.15, EC2.18, EC2.19, RDS.2, plus
  adoption of `plaintext-secret` and `external-can-assume`. Neither native
  finding maps cleanly to an FSBP control, so they carry NIST CSF 2.0
  references only. The FSBP catalogue also lists the next tranche's controls
  so the compliance report shows them as not-assessed rather than absent.
- Capabilities come from `DISCOVERY_CAPABILITIES` in adapters; a rule whose
  requirement is missing yields `not-assessed` per resource.
- Rule findings are written *into the stored snapshot graph* alongside adapter
  findings, so the map shows them without any viewer change. Lifecycle lives
  in the `findings` table; `reconcile` is one transaction per scan.
- Suppressions match `ruleId` + resource pattern (exact, `*`, or glob) with
  optional account scope and expiry; creating or revoking one re-applies to
  open findings immediately through the API, not just at the next scan.
- Rule and control metadata are mirrored into `rules` / `controls` tables at
  worker start (`syncRuleMetadata`); the API reads the registry directly.
- Not done here: `replaces` is enforced at registration but lifecycle rows are
  not yet migrated on rename (no rule has been renamed). A viewer inspector
  tab for controls and remediation is Phase 6.


**Goal.** Every snapshot is evaluated by a typed rule registry. Findings have
an open/resolved/suppressed lifecycle. Consecutive snapshots are diffed.

**Deliverables.**

- `@kumomiru/rules` (`packages/rules/src/`)
  - `types.ts` — `Rule`, `RuleContext`, `RuleResult` (`pass | fail |
    not-applicable | not-assessed`), `ControlRef`, `Remediation { text, cli?,
    terraform? }`.
  - `registry.ts` — id-unique registry. Each rule declares `requires:
    string[]` (collector capabilities). A rule whose collector was absent
    reports `not-assessed`, never `pass`.
  - `run.ts` — `evaluate(graph, registry) → { results, findings }`. Finding
    ids are deterministic: `f-<ruleId>-<djb2(resourceId)>`, reusing the hash
    pattern already in `iam.ts` and `sanitize.ts`.
  - `frameworks/fsbp.ts`, `frameworks/nist-csf-2.ts` — control catalogues and
    rule→control mappings, authored and versioned in-house (see §9).
  - `compliance.ts` — per-control roll-up: pass/fail/not-assessed per account.
  - `checks/<service>/*.ts` — first tranche limited to what the graph carries
    today: security group open to `0.0.0.0/0` or `::/0` on admin ports
    (EC2.13, EC2.14, EC2.18, EC2.19), RDS `PubliclyAccessible` (RDS.2),
    subnet auto-assign public IP (EC2.15), the existing plaintext-secret and
    external-can-assume findings.
- The two existing adapter-emitted finding kinds (`plaintext-secret`,
  `external-can-assume`) are **registered as rule metadata** so they get
  control ids, remediation, and lifecycle without moving the detection code
  out of `sanitize.ts` and `iam.ts`.
- `@kumomiru/graph`
  - `diff.ts` — `diffSnapshots(prev, next)` → nodes added/removed/changed
    (attribute hash), edges likewise, findings new/resolved.
  - `lifecycle.ts` — `FindingRecord`, `FindingStatus`.
  - `controls.ts` — `ControlRef` schema.
- Worker `jobs/scan.ts` step 2: run rules → diff against previous snapshot →
  upsert finding lifecycle (present → `open` or reopened; absent → `resolved`
  with `resolvedAt`; suppression match → `suppressed`) → write `rule_results`
  and `scan_diffs`.
- Server: `routes/findings.ts` (filter by account, status, severity, rule,
  control), `routes/suppressions.ts` (create, expire; admin), `routes/rules.ts`
  (registry metadata for the UI).

**Permissions added.** None.

**Schema deltas.** `Finding` gains optional `ruleId`, `source`, `controls`,
`remediation`, `resourceType`, `evidence`. `redactGraph` drops `evidence`.

**Exit criterion.** A scan produces a `rule_results` row for every registered
rule. A finding that disappears between two scans flips to `resolved`. A
suppression hides a finding from the open list and shows it under suppressed.
The compliance roll-up returns per-control pass/fail counts for both
frameworks.

**Parallelism.** Runs alongside Phase 3. Rules are authored against fixture
graphs in `packages/rules/test/fixtures`.

---

### Phase 3 — Resource coverage and resource-policy IAM (done, 2026-09-19)

Landed in two commits: tranche A (collector split, resource-policy pass, the
account/storage/audit services) and tranche B (the rest). Specifics:

- `discover.ts` is now an orchestrator over `aws-live/collectors/{network,
  compute, database, serverless, storage, security, iam}.ts` sharing a
  `CollectContext`; the existing 51 adapter tests passed unchanged across
  the split.
- New optional `DiscoveryClient` methods (all implemented by the SDK client):
  `accountSummary`, `credentialReport`, `cloudTrails`, `regionSettings`,
  `s3Buckets`, `ebsVolumes`, `ebsSnapshots`, `kmsKeys`; plus
  `flowLogsEnabled` on VPCs, `storageEncrypted` on RDS, resource policy and
  URL auth on Lambda, rotation and resource policy on secrets. A client
  declares extra capabilities via `capabilities()`; `graph.meta.capabilities`
  is the authoritative list the worker hands to the rule engine.
- New node types: `aws::s3::bucket`, `aws::kms::key`, `aws::ec2::volume`,
  `aws::ec2::snapshot`, `aws::cloudtrail::trail`. Account-level facts (root
  MFA/keys, password policy, account PAB, multi-region trail) live on the
  `aws::account` node; region-level facts (EBS default encryption, Config,
  GuardDuty) on the `aws::region` node. Users carry credential-report fields.
- `analysis/resourceAccess.ts`: `can-access` iam edges from resource
  policies (S3, KMS, Lambda, Secrets Manager) with `public-resource` and
  `external-can-access` findings; same-account root grants resolve through
  identity policies. Deny statements are not modeled (documented). A
  `regional` pass has no principals, so only public/external grants produce
  edges there; the `all` and merged paths see both.
- Shared `projectPolicyDocument` (adapters `common/policy-doc.ts`) parses
  JSON, URL-encoded, or object documents with principals; the SDK client and
  Terraform use it.
- 25 new rules: IAM.3/4/5/7/8/9, S3.1/2/5/8/9, EC2.1/3/6/7, RDS.3, KMS.4,
  CloudTrail.1/2/4, Config.1, GuardDuty.1, Lambda.1, SecretsManager.1, plus
  adoption of `public-resource` / `external-can-access`. 30 rules total.
- Policy: 34 new actions, all Describe/List/Get except
  `iam:GenerateCredentialReport` (documented exception in the test; it
  builds a metadata CSV). Still no `s3:GetObject`, `kms:Decrypt`,
  `GetSecretValue`.
- Terraform parity: `aws_s3_bucket`, `aws_kms_key`, `aws_ebs_volume`,
  `aws_cloudtrail` mapped. Bucket policies from `aws_s3_bucket_policy` are
  not yet linked to their bucket (needs a cross-resource pass).
- **Tranche B** adds 21 node types: route tables (subnets get
  `public: true` when their table sends 0.0.0.0/0 to an IGW, main-table
  inheritance included), NAT gateways, VPC peering (cross-account flagged),
  VPC endpoints, NACLs, ELBv2 (internet-facing LBs get the same red
  `allows-ingress` edge instances do, plus `targets` dataflow edges), ECS
  clusters/services/task definitions (env vars sanitized), EKS, SQS, SNS,
  DynamoDB (live), ECR, Auto Scaling groups and launch templates (user-data
  sanitized), EFS, CloudFront (global pass; origin edges when the bucket is
  in the graph), API Gateway REST APIs, RDS clusters and snapshots, SSM
  parameters (metadata only; SecureString listed as a secret-shaped node).
  SQS, SNS, ECR, and EFS policies feed the resource-access pass.
  Instances carry `imdsv2Required`.
- 21 tranche-B rules (EC2.2/8/21, AutoScaling.3, ELB.1/5, ECS.2, EKS.1/8,
  SQS.1, SNS.1, DynamoDB.2, ECR.1/2/3, EFS.1, CloudFront.3/5, APIGateway.1,
  RDS.1/27). **51 rules total**, mapping 50 FSBP controls. Remaining
  visible gaps: IAM.6 (hardware MFA, not distinguishable from the API) and
  ECS.8 (covered in substance by the plaintext-secret scan on task
  definitions, but not mapped to avoid claiming it for EC2 user-data).
- 45 more actions in the policy; `apigateway:GET` joins
  `iam:GenerateCredentialReport` as a documented exception to the
  Describe/List/Get shape (it is how API Gateway names every read).
- Terraform: `aws_s3_bucket_policy` is joined to its bucket and the
  resource-access pass runs on Terraform graphs; Terraform meta now carries
  `capabilities` and a real `generatedAt`.
- **Still not collected:** EIPs, security-group egress rules (EC2.2 checks
  ingress only, stated in the rule), RDS parameter groups, Lambda layers,
  WAF, Route 53, ACM. None blocks a current rule.


**Goal.** Collect what FSBP controls actually need. Feed resource-based
policies into the IAM brain so "who can read this secret" becomes true.

**Deliverables.**

- Refactor `discover.ts` into `aws-live/collectors/{network, compute, storage,
  database, messaging, iam, security}.ts`. Each collector is `(client, ctx) →
  Partial<{ nodes, edges, findings, resourcePolicies, ... }>`; `discoverGraph`
  composes them. `DiscoveryClient` gains **optional** methods per new resource,
  following the existing `users?()` pattern, so fake clients still compile and
  rules report `not-assessed` when a method is absent.
- **Tranche A** (ordered in §6): IAM credential report, password policy,
  account summary; S3 buckets plus account-level Public Access Block; EBS
  volumes, snapshots, default encryption; route tables, NAT gateways, peering,
  flow logs, NACLs, VPC endpoints, EIPs; KMS keys and rotation; CloudTrail;
  Config recorder; GuardDuty detector; RDS clusters and snapshots; Lambda
  resource policy and function URLs; Secrets Manager resource policy and
  rotation; SSM parameter metadata (never values).
- **Tranche B**: ELBv2 listeners and target groups; EKS; ECS (task-definition
  env vars through `sanitize`); SQS; SNS; DynamoDB; ECR; Auto Scaling groups
  and launch templates (user-data through `sanitize`); EFS; CloudFront; API
  Gateway.
- `analysis/policy.ts` gains `PolicyStatement.principals` and
  `evaluateResourcePolicy(stmts, principal, action, resource)`.
- New `analysis/resourceAccess.ts` — `analyzeResourceAccess(principals,
  resources)` emits `lens: "iam"` `can-access` edges (identity allow ∩
  resource-policy allow, or resource-policy alone for `*` and external
  principals) plus `external-can-access` and `public-resource` findings. This
  is what makes the DESIGN §6 signature view real: click a secret, see every
  principal that can read it.
- Terraform adapter parity in `terraform/mappings.ts` for at least S3, KMS,
  SQS, SNS, and ELB.
- Viewer glyphs, accents, and humanized labels in `lib/icons.ts`,
  `lib/style.ts`, `lib/format.ts` for every new type. The `aws::iam::user`
  gap in `PLANNED_IMPROVEMENTS.md` shows what happens otherwise.
- New edge relationships: `can-access`, `routes-to`, `encrypted-by`,
  `logs-to`, `targets`.

**Permissions added.** All Read/List, generated into the policy.

Tranche A:

```
s3:ListAllMyBuckets s3:GetBucketLocation s3:GetBucketPolicy
s3:GetBucketPolicyStatus s3:GetBucketPublicAccessBlock s3:GetBucketAcl
s3:GetEncryptionConfiguration s3:GetBucketVersioning s3:GetBucketLogging
s3:GetLifecycleConfiguration s3:GetBucketTagging s3control:GetPublicAccessBlock
ec2:DescribeVolumes ec2:GetEbsEncryptionByDefault ec2:DescribeSnapshots
ec2:DescribeSnapshotAttribute ec2:DescribeRouteTables ec2:DescribeNatGateways
ec2:DescribeVpcPeeringConnections ec2:DescribeFlowLogs ec2:DescribeNetworkAcls
ec2:DescribeVpcEndpoints ec2:DescribeAddresses
kms:ListKeys kms:DescribeKey kms:GetKeyRotationStatus kms:GetKeyPolicy kms:ListAliases
cloudtrail:DescribeTrails cloudtrail:GetTrailStatus cloudtrail:GetEventSelectors
iam:GenerateCredentialReport iam:GetCredentialReport iam:GetAccountPasswordPolicy
iam:GetAccountSummary iam:ListVirtualMFADevices
rds:DescribeDBClusters rds:DescribeDBSnapshots rds:DescribeDBSnapshotAttributes
rds:DescribeDBClusterSnapshots
lambda:GetPolicy lambda:ListFunctionUrlConfigs
secretsmanager:DescribeSecret secretsmanager:GetResourcePolicy
ssm:DescribeParameters
config:DescribeConfigurationRecorders config:DescribeConfigurationRecorderStatus
guardduty:ListDetectors guardduty:GetDetector
```

Tranche B:

```
elasticloadbalancing:DescribeLoadBalancers elasticloadbalancing:DescribeListeners
elasticloadbalancing:DescribeTargetGroups elasticloadbalancing:DescribeTargetHealth
elasticloadbalancing:DescribeLoadBalancerAttributes
eks:ListClusters eks:DescribeCluster
ecs:ListClusters ecs:DescribeClusters ecs:ListServices ecs:DescribeServices
ecs:ListTaskDefinitions ecs:DescribeTaskDefinition
sqs:ListQueues sqs:GetQueueAttributes sns:ListTopics sns:GetTopicAttributes
dynamodb:ListTables dynamodb:DescribeTable dynamodb:DescribeContinuousBackups
ecr:DescribeRepositories ecr:GetRepositoryPolicy ecr:GetRegistryScanningConfiguration
autoscaling:DescribeAutoScalingGroups ec2:DescribeLaunchTemplates
ec2:DescribeLaunchTemplateVersions
elasticfilesystem:DescribeFileSystems elasticfilesystem:DescribeFileSystemPolicy
cloudfront:ListDistributions cloudfront:GetDistributionConfig
apigateway:GET
```

**Schema deltas.** None structural. New node types and edge relationships only.

**Exit criterion.** FSBP controls for S3, EBS, KMS, CloudTrail, IAM, RDS, and
EC2 evaluate `pass` or `fail` (not `not-assessed`) against a real account. A
public S3 bucket policy produces a bold red `can-access` edge from the `*`
principal and a critical finding. A Secrets Manager secret's "Who can reach
this?" lists real `can-access` principals.

**Parallelism.** Tranche A alongside Phase 2. Tranche B alongside Phases 4
and 5.

---

### Phase 4 — Managed feeds: Security Hub and IAM Access Analyzer

**Goal.** Ingest AWS-computed findings as first-class findings. Fall back to
native rules where the services are off.

**Deliverables.**

- `@kumomiru/aws/collectors/securityhub.ts` — `DescribeHub` as the enabled
  gate, `GetEnabledStandards`, paginated `GetFindings` filtered to
  `RecordState=ACTIVE` and `WorkflowStatus in (NEW, NOTIFIED)`.
- `@kumomiru/aws/collectors/accessanalyzer.ts` — `ListAnalyzers`, then
  `ListFindingsV2` per analyzer.
- `@kumomiru/adapters/src/feeds/asff.ts` — maps ASFF to
  `Finding { source: "securityhub", externalId: findingArn, ruleId:
  "securityhub.<GeneratorId>", controls from Compliance.SecurityControlId and
  AssociatedStandards }`. The resource ARN becomes `nodeId` when present in
  the graph; otherwise the finding stands alone, which the schema already
  allows.
- `@kumomiru/adapters/src/feeds/accessanalyzer.ts` — external-access findings
  become `lens: "iam"` edges attributed `source: "accessanalyzer"`. They
  supersede native `external-can-*` findings for the same resource and
  principal.
- Rules: a rule may declare `supersededBy: "securityhub"`. When the feed
  delivered the same `SecurityControlId` for the account and region, the native
  rule yields "covered by Security Hub". Otherwise it runs. **This is the
  graceful fallback**, and it is automatic.
- Worker `jobs/feeds.ts` runs inside the scan job after collection. ASFF
  free-text fields pass through `sanitize`.

**Permissions added.**

```
securityhub:DescribeHub securityhub:GetEnabledStandards securityhub:GetFindings
securityhub:DescribeStandardsControls
access-analyzer:ListAnalyzers access-analyzer:ListFindings
access-analyzer:ListFindingsV2 access-analyzer:GetFinding access-analyzer:GetFindingV2
```

**Schema deltas.** `Finding.source` enum gains `securityhub` and
`accessanalyzer`. `Finding.externalId`, `Finding.observedAt`. Edge attribute
convention `attributes.source`.

**Exit criterion.** An account with Security Hub FSBP enabled shows feed
findings with control ids and no duplicate native finding for the same control
and resource. An account without Security Hub shows native results for the
same controls. An Access Analyzer public-bucket finding renders as a bold red
edge exactly like native external access.

**Parallelism.** After Phase 2 and Phase 3 tranche A. Overlaps Phase 5.

---

### Phase 5 — Auth, RBAC, Organizations onboarding

**Goal.** Multi-user access and org-scale onboarding without storing cloud
keys.

**Deliverables.**

- Server `auth/`
  - `oidc.ts` — `openid-client`, discovery for Okta, Entra, Google, PKCE.
  - `session.ts` — signed HttpOnly cookie.
  - `guard.ts` — `preHandler` requiring `viewer` or `admin`.
  - `routes/auth.ts` — `/auth/login`, `/auth/callback`, `/auth/logout`,
    `/auth/me`. Bootstrap: emails in `KUMOMIRU_ADMIN_EMAILS` become admin on
    first login.
  - Extend `REDACT_PATHS` in `packages/server/src/redact.ts` for cookies and
    id tokens.
- Viewer: `views/Login.tsx`, route guard, role-aware controls.
- Organizations
  - `@kumomiru/aws/collectors/organizations.ts` — `DescribeOrganization`,
    `ListRoots`, `ListOrganizationalUnitsForParent`, `ListAccountsForParent`,
    `ListAccounts`, `ListTagsForResource`.
  - Worker `jobs/orgSync.ts` — discover accounts → upsert with
    `status: pending | active | inactive` and OU path.
  - Server `routes/onboarding.ts` — `GET /onboarding/stackset.yaml` renders a
    CloudFormation template that creates `KumomiruScanRole` with the generated
    least-privilege policy and a trust policy for the worker host role ARN plus
    ExternalId. `POST /accounts/:id/verify` enqueues a worker job that assumes
    the role and calls `GetCallerIdentity` only.
  - **The operator deploys the StackSet.** kumomiru never calls
    `CreateStackSet` or any other write.
- `analysis/stitch.ts` — when a trusted account is also scanned, replace the
  synthesized `aws::iam::external-principal` node with the real principal node.
  Edge attribute `knownAccount: true`. The rule for "external but in-org"
  severity is explicit and documented so the flagship finding stays
  trustworthy.

**Permissions added** (worker host role only, in the management or delegated
admin account):

```
organizations:DescribeOrganization organizations:ListRoots
organizations:ListOrganizationalUnitsForParent organizations:ListAccountsForParent
organizations:ListAccounts organizations:ListTagsForResource
```

**Schema deltas.** None in `Graph`. `accounts` rows gain `ouPath`, `orgId`,
`onboarding: manual | organizations`.

**Exit criterion.** Login through an Okta test tenant. A `viewer` cannot hit
`POST /accounts`. Org sync lists every member account. Deploying the generated
StackSet to an OU makes those accounts `active` on the next verify. Scanning a
trusted sibling account converts an "external" finding into an in-org edge.

**Parallelism.** OIDC and RBAC can start right after Phase 1. Org onboarding
after Phase 1.

---

### Phase 6 — UI: dashboard, map posture overlays, history

**Goal.** Both map-first and dashboard-first, with an operator-switchable
default home.

**Deliverables.**

- Viewer restructure. `packages/viewer/src/App.tsx` becomes a shell with
  `react-router`. The current map moves to `views/MapView.tsx`. New views:
  - `Dashboard.tsx` — posture score per account, open findings by severity,
    control pass rate per framework, trend from `scan_diffs`.
  - `Findings.tsx` — table, filters, lifecycle actions, suppress dialog with
    reason and expiry.
  - `Compliance.tsx` — framework → control → failing resources.
  - `Accounts.tsx`, `History.tsx` (snapshot picker, diff summary),
    `Settings.tsx` (default home, alert channels).
- Map overlays in `lib/elements.ts` and `lib/style.ts`. Extend the existing
  `worstSeverityByNode` halo with a posture badge (fail count), a change badge
  (added or changed since the previous snapshot), and later a drift badge.
  Overlay toggles sit beside `LensToggle`. **These are overlays, not lenses.**
  `LENSES` stays at three.
- Inspector: controls tab (rule, control ids, remediation text with copy
  buttons for the CLI and Terraform snippets), first/last seen, suppress
  action.
- Server: `routes/dashboard.ts` (aggregates), `routes/settings.ts`
  (`ui.defaultHome`), snapshot diff endpoint on `routes/snapshots.ts`.
- API response types (`FindingRecord`, `SnapshotDiff`, `ControlStatus`) are
  exported from `@kumomiru/graph` so the viewer validates them the way it
  validates a `Graph` today.

**Permissions added.** None.

**Exit criterion.** The operator sets the default home to the dashboard.
Clicking a failing control lands on the map with the offending nodes
spotlighted. Suppressing from the inspector updates status without a reload.
The history view shows a resource that appeared between two scans.

**Parallelism.** Needs Phases 2 and 5. Runs alongside Phase 7.

---

### Phase 7 — Alerting and compliance reports

**Goal.** Push new or reopened findings out. Export compliance status.

**Deliverables.**

- Worker `alerts/`
  - `dispatch.ts` — triggered by lifecycle transitions (`new`, `reopened`,
    optionally `resolved`), filtered per channel by minimum severity, accounts,
    and rule ids.
  - `webhook.ts` — JSON POST with `X-Kumomiru-Signature: t=<ts>,v1=<hmac-sha256>`,
    retry with backoff.
  - `linear.ts` — GraphQL `issueCreate` and `issueUpdate`. One issue per
    finding id, tracked in `alert_deliveries.external_ref`. Comment and close
    on resolve.
  - Channel secrets encrypted at rest with AES-256-GCM under
    `KUMOMIRU_MASTER_KEY`, never logged (extend `redactObject`).
- Server `routes/alerts.ts` — channel CRUD, test-send; admin only.
- Server `routes/reports.ts` —
  `GET /reports/compliance?framework=fsbp|nist-csf-2&account=&format=csv|json`
  from `rule_results` and `controls`, and `GET /reports/findings.csv`.
- `@kumomiru/rules/compliance.ts` produces the row model shared by both
  formats.

**Permissions added.** None.

**Exit criterion.** A new critical finding produces exactly one signed webhook
POST and one Linear issue. Resolving it comments and closes the issue. The CSV
opens in a spreadsheet with one row per control per account showing pass, fail,
and not-assessed counts and the failing resource ids.

**Parallelism.** Alongside Phase 6.

---

### Phase 8 — IaC drift: declared intent

**Goal.** Mark every live resource as managed or unmanaged, and surface
declared-versus-deployed drift from CloudFormation, CDK, and Terraform through
one abstraction.

**How CDK fits.** CDK synthesizes to CloudFormation. Every CDK-deployed
resource carries `aws:cloudformation:stack-name`, `stack-id`, and `logical-id`
tags, and CloudFormation tracks the stack's resources and drift status. So the
live CloudFormation API alone attributes CDK infra with no pipeline
integration. The `cdk.out` cloud assembly (a `manifest.json` plus templates)
adds the declared side, so undeployed or out-of-band-deleted resources are
visible too. kumomiru never runs `cdk synth` or the user's TypeScript.

**Deliverables.**

- `@kumomiru/adapters/src/intent/`
  - `types.ts` — `DeclaredIntent { source: "cloudformation" | "cdk-assembly" |
    "terraform-state", units: [{ name, resources: [{ logicalId, cfnType |
    tfType, physicalId?, nodeType, propsHash }] }] }`.
  - `cfnTypes.ts` — CloudFormation type → kumomiru node type. Shared by live
    stacks and templates.
  - `cloudformation.ts` — from live `DescribeStacks`, `ListStackResources`,
    `DescribeStackResourceDrifts`.
  - `cdkAssembly.ts` — parse `cdk.out/manifest.json`, feed each template
    through the same path as a CloudFormation template upload. Template bodies
    pass through `sanitize`.
  - `terraform.ts` — reuse the parser in `terraform/index.ts`; emit intent
    instead of a graph.
  - `compare.ts` — `compareIntent(graph, intents[])` → managed, unmanaged,
    declared-not-deployed, deployed-not-declared, drifted.
- Live tag attribution in collectors: `aws:cloudformation:*` tags →
  `node.attributes.managedBy = { kind: "cloudformation", stackId, logicalId }`.
  Terraform intent marks nodes by ARN or id match.
- Worker `jobs/drift.ts` runs after the scan. Triggering `DetectStackDrift` is
  a per-account setting, **default off** (see §9).
- Rules `checks/drift/*.ts` emit `source: "drift"` findings:
  `drift.unmanaged-resource`, `drift.stack-drifted`,
  `drift.declared-not-deployed`, `drift.deployed-not-declared`.
- Server `routes/intent.ts` — upload a `cdk.out` zip, a CloudFormation
  template, or a tfstate. Stored as sanitized `declared_intent` rows.
  Upload is the default path for all three sources.
- **Terraform S3 backend, opt-in.** An operator may register a state backend
  per account: bucket ARN, optional key prefix, optional KMS key ARN. The
  generated scan-role policy then adds a separate statement
  (`Sid: KumomiruTerraformStateBucket`) granting `s3:GetObject` and
  `s3:ListBucket` on that bucket and prefix only, plus `kms:Decrypt` on the one
  named key if the bucket uses SSE-KMS. The worker `jobs/drift.ts` fetches the
  state through the same `CredentialBroker` run and passes it through
  `sanitize` before it becomes intent. This is the only sanctioned break in the
  "no data-plane reads" guarantee (§1), it is off by default, and the
  onboarding UI must show the exact statement being added.
- Viewer: drift overlay, and a "Managed by" section in the inspector.

**Permissions added.**

```
cloudformation:DescribeStacks cloudformation:ListStacks
cloudformation:ListStackResources cloudformation:DescribeStackResourceDrifts
cloudformation:DescribeStackDriftDetectionStatus
```

`cloudformation:DetectStackDrift` goes in a separate statement
(`Sid: KumomiruOptionalDriftTrigger`) so operators can omit it. The Terraform
state bucket statement (`Sid: KumomiruTerraformStateBucket`, `s3:GetObject`
and `s3:ListBucket` on one bucket ARN and prefix, optional `kms:Decrypt` on one
key) is likewise separate and generated only when the operator registers a
backend. Deliberately
**not** `cloudformation:GetTemplate`: template bodies can embed secrets, so
declared intent comes from uploads.

**Schema deltas.** `CloudNode.managedBy?` promoted from attributes to a typed
optional field once stable. `Finding.source` gains `drift`.

**Exit criterion.** A CDK-deployed VPC shows as managed with its stack and
logical id. A hand-created EC2 instance raises `drift.unmanaged-resource`.
Uploading a `cdk.out` whose template adds a security group not yet deployed
yields `drift.declared-not-deployed`. A tfstate upload marks its resources as
managed on the live map.

**Parallelism.** Last. Depends on Phases 1, 2, 3, and 6.

---

## 5. Schema evolution

Principle: **`Graph` stays a pure point-in-time snapshot.** Lifecycle state
(status, first and last seen) lives in database rows and API-only types, never
inside `Graph`. That keeps `sample.ts`, both adapters, `redactGraph`,
`checkReferentialIntegrity`, and the viewer working unchanged.

### Additions to `FindingSchema` (all optional; `kind` stays as the coarse category)

| Field | Type | Purpose |
|---|---|---|
| `ruleId` | `string` | Registry id, e.g. `s3.public-access-block`, `kumomiru.external-can-assume` |
| `source` | `"native" \| "securityhub" \| "accessanalyzer" \| "drift"` (default `native`) | Where the finding came from |
| `controls` | `{ framework: "fsbp" \| "nist-csf-2", id: string }[]` | Framework mapping |
| `remediation` | `{ text, cli?, terraform? }` | Operator guidance |
| `resourceType` | `string` | Survives node deletion for resolved findings |
| `evidence` | `record<unknown>` | Sanitized values the rule saw; `redactGraph` drops it |
| `externalId` | `string` | Security Hub finding ARN or Access Analyzer finding id |
| `observedAt` | `string` | Feed timestamp |

### Additions to `GraphMetaSchema` (all optional)

`accountId`, `regions: string[]`, `snapshotId`, `scanId`, `feeds: string[]`
(which managed feeds were available for this snapshot).

### `CloudNodeSchema` and `CloudEdgeSchema`

No change until Phase 8, which adds the optional `managedBy` object. New
information goes into `attributes` per the existing convention. Feed-derived
edges use `attributes.source`.

### New API-only schemas exported from `@kumomiru/graph`

Separate files, not part of `GraphSchema`:

- `FindingRecordSchema = FindingSchema.extend({ status, firstSeenAt,
  lastSeenAt, resolvedAt?, suppressionId?, accountId, snapshotId })`.
- `ResourceRecordSchema` — `id, type, accountId, region?, firstSeenAt,
  lastSeenAt, firstSnapshotId, lastSnapshotId`.
- `SnapshotDiffSchema`, `ControlStatusSchema`.

### Finding id stability

Ids are deterministic from `(ruleId, resourceId[, principal])` via the existing
djb2 pattern. A rule that changes its id declares `replaces: [oldId]` so
lifecycle rows migrate instead of resolving and reopening.

`checkReferentialIntegrity` keeps its semantics. Findings with a non-native
source may omit `nodeId`, which the schema already allows.

---

## 6. Resource coverage order

Ordered by how many FSBP controls each unlocks per unit of collector work.

| # | Resources | FSBP controls unlocked | Notes |
|---|---|---|---|
| 1 | IAM credential report, password policy, account summary, root MFA | IAM.1–9, IAM.18, IAM.22 | Cheapest, highest control count |
| 2 | S3 buckets + account Public Access Block | S3.1–3, S3.5, S3.8, S3.9, S3.17, S3.19 | Bucket policy feeds `analyzeResourceAccess` |
| 3 | Route tables, NAT, peering, flow logs, NACLs, endpoints, EIPs, EBS volumes, default encryption, public snapshots | EC2.1–3, EC2.6–8, EC2.13–15, EC2.18–21 | Also completes the network lens with `routes-to` edges and real internet reachability |
| 4 | KMS keys | KMS.1–4 | `encrypted-by` edges to S3, EBS, RDS, SQS, SNS, secrets |
| 5 | CloudTrail, Config recorder, GuardDuty | CloudTrail.1–7, Config.1, GuardDuty.1 | Account-level |
| 6 | RDS clusters and snapshots, Lambda policy and URLs, Secrets Manager rotation and policy, SSM parameter metadata | RDS.1, RDS.3–13, Lambda.1–3, SecretsManager.1–4 | |
| 7 | ELBv2 | ELB.1–10, ELBv2.1 | `targets` edges (LB → target group → instance) close the dataflow lens's biggest gap |
| 8 | ECS, EKS, ECR | ECS.1–5, ECS.8, EKS.1–3, EKS.8, ECR.1–3 | Task-definition env vars through `sanitize` |
| 9 | SQS, SNS, DynamoDB, EFS | SQS.1, SNS.1–2, DynamoDB.1–4, EFS.1–4 | Resource policies into `analyzeResourceAccess` |
| 10 | Auto Scaling, launch templates, CloudFront, API Gateway | AutoScaling.1–9, CloudFront.1–13, APIGateway.1–9 | Launch-template user-data through `sanitize` |

Every type with a resource policy (S3, KMS, Lambda, Secrets Manager, SQS, SNS,
ECR, EFS, and role trust already) is projected to `PolicyStatement[]` with
principals and passed to `analyzeResourceAccess`. The identity side reuses the
existing evaluator with the real action: `s3:GetObject`,
`secretsmanager:GetSecretValue`, `kms:Decrypt`, `sqs:ReceiveMessage`.

---

## 7. SQLite schema sketch

`packages/db/migrations/0001_init.sql` onward. Types abbreviated.

```
accounts        id PK (12-digit), name, role_arn, external_id, regions_json,
                schedule_cron, onboarding (manual|organizations), org_id, ou_path,
                status (pending|active|inactive), created_at, updated_at
scans           id PK, account_id FK, started_at, finished_at,
                status (queued|running|ok|failed|partial), trigger (schedule|manual|verify),
                regions_json, error_json (redacted), worker_id, stats_json
snapshots       id PK, scan_id FK, account_id FK, generated_at, source,
                graph_json (Graph, optionally zlib), node_count, edge_count,
                finding_count, prev_snapshot_id
snapshot_resources
                snapshot_id FK, resource_id, type, attr_hash
                PK (snapshot_id, resource_id)        -- cheap SQL diffs, per-resource history
resources       id PK (ARN), account_id, type, region, name, first_seen_at,
                last_seen_at, first_snapshot_id, last_snapshot_id, managed_by_json
findings        id PK, account_id, rule_id, source, severity, kind,
                resource_id NULL, resource_type, status (open|resolved|suppressed),
                title, detail, controls_json, remediation_json, evidence_json,
                external_id, first_seen_at, last_seen_at, resolved_at,
                last_snapshot_id, suppression_id NULL
rule_results    snapshot_id FK, rule_id, resource_id, status (pass|fail|na|not-assessed)
                PK (snapshot_id, rule_id, resource_id)
rules           id PK, version, title, severity, resource_types_json, controls_json,
                requires_json, remediation_json, enabled, updated_at
                -- synced from the registry at worker start
controls        framework, id, title, description   PK (framework, id)
rule_controls   rule_id, framework, control_id
suppressions    id PK, rule_id, resource_pattern (glob|exact), account_id NULL,
                reason, created_by FK users, created_at, expires_at NULL, revoked_at NULL
scan_diffs      snapshot_id PK, prev_snapshot_id, diff_json
users           id PK, email UNIQUE, name, idp_subject, idp_issuer,
                role (viewer|admin), created_at, last_login_at, disabled
sessions        id PK, user_id FK, expires_at, created_at
alert_channels  id PK, kind (webhook|linear), name, config_json, secret_enc BLOB,
                min_severity, filters_json, enabled
alert_deliveries
                id PK, channel_id FK, finding_id FK, event (new|reopened|resolved),
                status, attempts, external_ref, last_error, created_at
declared_intent id PK, account_id NULL, source (cloudformation|cdk-assembly|terraform-state),
                name, uploaded_by FK users, uploaded_at, intent_json (sanitized)
settings        key PK, value_json
worker_leases   name PK, holder, expires_at
```

Indexes: `findings(account_id, status, severity)`, `findings(rule_id)`,
`snapshots(account_id, generated_at DESC)`, `rule_results(rule_id, status)`.

Retention: keep the last N snapshots per account with daily and weekly thinning.
`resources` and `findings` rows persist regardless of snapshot retention. If
`rule_results` cardinality grows, add a daily `control_rollups` table.

---

## 8. Dependency graph

```
Phase 1 ──┬──▶ Phase 2 ──┬──▶ Phase 4 (needs 3A too)
          │              ├──▶ Phase 6 (needs 5 too) ──▶ Phase 8 (needs 3 too)
          │              └──▶ Phase 7
          ├──▶ Phase 3 (A alongside 2; B alongside 4, 5)
          └──▶ Phase 5 (auth immediately; org onboarding after 1)
```

Two engineers can work Phases 2 and 3A in parallel from the day Phase 1 lands.
Phase 5 auth is independent of the rule engine and can be a third track.

---

## 9. Risks and open questions

- **SQLite deployment shape.** One host, one worker, one API, local disk. No
  NFS. Document it as the supported unit until the Postgres repository exists.
  The server must never write snapshot-family tables.
- **API throttling at org scale.** `GetAccountAuthorizationDetails` is large,
  and many accounts times many regions will hit rate limits. Per-service
  concurrency caps, exponential backoff, and a `partial` scan status are
  required from Phase 1, not bolted on.
- **ExternalId scope.** Per org or per account? Where is it shown? It is not a
  secret but must not be guessable.
- **Framework mappings are in-house.** FSBP controls change quarterly. Security
  Hub maps to NIST SP 800-53, not CSF v2, so the CSF v2 mapping is authored and
  versioned by us. Someone must own its review.
- **Rule versioning versus lifecycle.** Does a stricter rule "reopen" a
  finding or create a new one? The `replaces` mechanism handles renames; a
  policy for semantic changes is still needed.
- **`DetectStackDrift` is not purely read-only.** It starts an asynchronous
  operation and updates stack metadata. IAM classes it as Read, but some
  organizations treat it as a side effect. Default off, separate policy
  statement, and stated plainly in the onboarding docs.
- **Security Hub topology.** It is regional with an optional aggregation
  region. Access Analyzer has account and organization analyzers. Decide
  whether to read the aggregation region only.
- **Discovered secrets live longer in worker memory** than they did in a
  request handler. `sanitize` still redacts before the graph, but a worker
  crash dump holds more. Prefer short scan jobs and avoid retaining raw
  responses.
- **Snapshot storage growth.** `graph_json` for hundreds of accounts, across
  regions, on a schedule. Compression and the retention policy must exist
  before Phase 6 history views ship.
- **Viewer scale.** One map per account is fine. An org-wide map is not;
  Cytoscape and ELK degrade past a few thousand nodes. The dashboard is the
  org-level view, and the docs should say so.
- **Fate of the pasted-credential path.** Keep `POST /map/live` behind a flag,
  or remove it once assume-role onboarding exists?
- **`KUMOMIRU_MASTER_KEY`.** Rotation story, and whether an optional AWS KMS
  envelope on kumomiru's own key (read plus `kms:Decrypt` on one key it owns,
  not customer keys) is acceptable under "no cloud write access".
- **Terraform state bucket exception (decided).** The extended "no data-plane
  reads" guarantee stands, with one operator-opted-in `s3:GetObject` scoped to
  a single state bucket and prefix (Phase 8). Remaining question: whether the
  denylist test should also reject an exception statement whose bucket ARN
  contains a wildcard.
- **Cross-account stitching changes severity.** "External but in-org" must have
  an explicit rule so the flagship external-can-assume finding stays
  trustworthy.
- **Partitions.** GovCloud and China need partition-aware STS endpoints,
  Organizations, and ARN helpers. The current helpers hardcode `arn:aws:`.

---

## 10. Not in this roadmap

Named so nobody assumes they are coming for free:

- CIS AWS Foundations Benchmark mapping.
- Near-real-time change detection via EventBridge or AWS Config streams.
- Auto-remediation of any kind.
- Azure, GCP, or any second provider.
- Native Slack app, email digests, Jira.
- PDF posture reports.
- The local-agent ingestion mode from DESIGN §6A. Host-identity assume-role
  supersedes its motivation for now.
