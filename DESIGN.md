# kumomiru — Design

A public cloud environment mapper / visualizer. Ingests a cloud account's
resources (from exported files **or** a live read-only API key) and produces an
interactive, genuinely good-looking map of what exists and how it connects:
network topology, IAM reachability, and data flows.

> Status: pre-code design. This document is the source of truth for direction;
> it will be refined as the code lands.

---

## 1. Thesis

The differentiator is **visualization quality and ease of use**. Existing tools
(Cartography, CloudMapper, Steampipe, AWS Perspective, PMapper) are powerful but
query-heavy and visually poor — mostly force-directed hairballs or CLI/dot
output. The entire reason to build kumomiru is a genuinely nice interactive
visual layer over a correctly normalized cloud graph.

Cloud architectures are fundamentally **nested containment + directional flow**,
not blobs — so we lean on compound (nested) nodes and layered layout, never a
force-directed hairball.

---

## 2. Decisions locked for 1.0

| Area | Decision |
|---|---|
| Provider | **AWS first** (generalize later) |
| Map lenses | **All three** — network, IAM, dataflow — as a layered toggle over ONE shared node set |
| Form factor | **Self-hosted web app** (user runs it on their own infra) |
| Ingestion | **Both** exported files (Terraform state, AWS Config, CloudFormation) and live read-only AWS API, treated equally — both emit the same normalized `Graph` |
| Key handling | App does **not store** credentials. In-memory, per-run only; discover, build graph, discard. Avoids a secure key-storage scheme → faster to 1.0 |
| Renderer | **Cytoscape.js** + `cytoscape-elk` (layered layout) + `cytoscape-expand-collapse` (semantic zoom) |
| Backend language | **TypeScript everywhere** — shared graph types between backend and viewer, no schema drift, fastest to 1.0 |
| First IAM lens | **Assume-role graph only** (trust ∩ identity). Escalation taxonomy + Access Analyzer ingestion are later increments |
| Discovery location | **Server-side for 1.0**, but adapters designed so the same code can run as a **local CLI agent** (posts only the Graph; server never touches a key) post-1.0 |
| Discovered secrets | **Detect, redact, flag as a finding.** Never resolve secret values |

---

## 3. Architecture

The **normalized graph is the spine.** Every ingestion source normalizes into
one provider-agnostic model. Everything downstream (viewer, lenses, diff,
export) works only on that model and never touches a cloud SDK. This is what
makes "exported" and "live" just two adapters feeding the same pipeline.

```
                  ┌─────────────── credential broker (A) ───────────────┐
   creds (TLS) ──▶│  in-memory only · redacted logging · STS-preferred   │
                  │  drops creds after run                               │
                  └──────────────────────┬──────────────────────────────┘
                                         ▼
          ┌──────────┐   raw resources   ┌──────────────────────┐
adapters ─│ discovery│ ────────────────▶ │ sanitization layer(B)│  detect+redact
          └──────────┘                   │ secretPresent flags  │  → FINDINGS
                                         └──────────┬───────────┘
                                                    ▼
                                          NORMALIZED GRAPH (nodes)
                                                    │
                                ┌───────────────────┴───────────────────┐
                                ▼                                        ▼
                     network / dataflow edges          IAM ANALYSIS PASS (post-collection)
                     (emitted by adapters)             trust ∩ identity → can-assume
                                                        emits lens:'iam' edges
                                                    │
                                                    ▼
                                          Graph JSON ──▶ Cytoscape viewer
```

Key structural rules:

- **Adapters are dumb and side-effect-free.** An adapter is
  `(credentialProvider, options) => Promise<Graph>`. It lists resources and
  emits obvious (network/dataflow) edges. It never reads creds from
  global/env directly (so the same code runs server-side now and as a local
  agent later).
- **IAM is an analysis pass, not an adapter.** It runs *after* node collection,
  evaluates policies over the assembled node set, and emits `lens:'iam'` edges.
  The brain is one shared module regardless of ingestion source.
- **Two cross-cutting components at the adapter↔graph boundary:** the
  **credential broker** (consumed creds — see §6A) and the **sanitization
  layer** (discovered secrets — see §6B).

### Repo layout (planned)

```
kumomiru/
├── packages/
│   ├── graph/          # @kumomiru/graph — THE SPINE
│   │   ├── types.ts        # Node, Edge, Finding, Graph, Lens
│   │   ├── schema.ts       # Zod — runtime validation of exports & live output
│   │   └── sample.ts       # hand-authored demo graph (milestone 1)
│   ├── adapters/       # @kumomiru/adapters
│   │   ├── terraform/      # parse .tfstate → Graph   (no creds, first)
│   │   ├── aws-config/     # Config/CFN snapshot → Graph
│   │   └── aws-live/       # SDK v3 discovery → Graph  (in-memory creds)
│   ├── server/         # Fastify: POST /map → Graph JSON; drops creds after
│   └── viewer/         # React + Cytoscape; lens toggle, compound nodes
└── pnpm-workspace.yaml
```

Stack: pnpm workspaces · Node + TypeScript + Fastify · AWS SDK v3 ·
Vite + React + Cytoscape.js.

---

## 4. The data model (the spine)

The three lenses are **just edge subsets over one shared node set.** Toggling a
lens = filtering edges by their `lens` field. This is why "all three, layered"
is cheap *if* the schema is right and expensive if it isn't — so the schema is
milestone #1.

```ts
export type Lens = 'network' | 'iam' | 'dataflow';

export interface CloudNode {
  id: string;            // ARN / stable URN
  type: string;          // "aws::ec2::instance"
  name: string;
  account: string;
  region?: string;
  parent?: string;       // → Cytoscape compound containment
  tags: Record<string, string>;
  attributes: Record<string, unknown>;   // sanitized — never raw secret values
}

export interface CloudEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;  // contains | routes-to | can-assume | allows-ingress ...
  lens: Lens;            // ← powers the toggle
  attributes: Record<string, unknown>;
}

export interface Finding {
  id: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  kind: string;          // "plaintext-secret" | "external-can-assume" ...
  nodeId?: string;       // resource the finding is about
  title: string;
  detail: string;
}

export interface Graph {
  nodes: CloudNode[];
  edges: CloudEdge[];
  findings: Finding[];
  meta: { generatedAt: string; source: string; provider: 'aws' };
}
```

`Finding` is a first-class type from day one: the sanitization layer produces
"plaintext secret" findings, and the IAM pass later produces
"external principal can assume admin" findings.

Containment hierarchy drives Cytoscape compound nodes:
`account → region → VPC → AZ → subnet → resource`. This alone makes the map
read like a real architecture diagram.

---

## 5. The three lenses

### Network
From SG rules + route tables + subnet associations + IGW/NAT/peering →
reachability and internet exposure. Mostly observed facts.

### Dataflow
What talks to what — LBs → target groups → instances, Lambda → DynamoDB,
queues. Inferred from explicit refs and SG-allows + ports. Hardest to infer
cleanly.

### IAM (reachability) — see §6 for secrets interplay

IAM reachability is the **output of an analysis engine**, not an observation.
The question: *"What can principal X ultimately reach, including every
transitive hop and privilege-escalation trick?"* (the PMapper problem space).

**Principals (nodes):** IAM users, roles, groups, account root, service
principals (`lambda.amazonaws.com`), and external/federated principals
(SAML/OIDC, other accounts, `"AWS":"*"`). External principals are the IAM
analog of "internet exposure."

**Two edge families:**

```
can-assume        A→B : A may sts:AssumeRole B
                        REQUIRES BOTH A's identity policy allows
                                  AND B's trust policy permits A
                        ← #1 mis-modeled edge (people check only one side)

can-escalate-via  A→B : A can manipulate something to OBTAIN B's privileges
  :create-access-key, :set-policy, :pass-role+run, :pass-role+lambda,
  :policy-version, :rewrite-trust, :ssm-command, ...  (PMapper taxonomy)
```

Tag each edge **direct** (`can-assume` — quiet, legitimate-looking) vs **noisy
escalation** (requires creating/modifying resources — detectable). Defenders
triage on that axis.

**The four hard parts:**
1. **Real policy evaluation** — explicit-deny > allow > implicit-deny, combined
   across identity + resource-based + permission boundaries + SCPs + session
   policies. `SimulatePrincipalPolicy` ignores SCPs and much condition logic →
   local evaluation needed (PMapper does the same).
2. **Conditions** (`aws:MultiFactorAuthPresent`, `sts:ExternalId`,
   `aws:SourceIp`, tag matches) — often unresolvable statically. **Model edges
   as conditional, attach the unresolved condition, give users assumption
   toggles** ("assume MFA present"). A false hard edge kills trust in a security
   tool.
3. **Policy-language correctness** — action/ARN wildcard expansion, `NotAction`,
   `NotResource`. Tedious but solved (datasets exist).
4. **Transitive closure = the visualization payoff** — every valuable question
   is a graph query that maps to a great interaction:
   - "What can X reach?" → forward reachability subgraph
   - "Who can reach admin / this secret?" → reverse reachability to a target
   - "Shortest escalation path low-priv → admin" → highlighted, per-edge labeled
   - "Which external principals can get in?" → cross-account exposure

**Build vs borrow:** port PMapper (BSD) escalation taxonomy + local eval;
ingest IAM Access Analyzer findings as authoritative external-access edges
(AWS computes the hardest part); `GetAccountAuthorizationDetails` is the
collection backbone.

**Incremental rollout:**
1. **Assume-role graph only** (trust ∩ identity) — highest signal, cleanest to
   get *correct*. ← 1.0
2. Ingest Access Analyzer findings.
3. Port the escalation taxonomy.

Don't try to be a perfect policy simulator on day one; be correct about the
simple cases and honest about conditions.

---

## 6. Secrets management — two distinct concerns

### (A) The credential we *consume* to scan

"In-memory, never stored" handles the headline, but a long-lived server process
has sharp edges:

| Leak vector | Mitigation |
|---|---|
| SDK debug / request logs, stack traces | Redaction middleware on **all** logging; never log the cred object |
| Crash/core dumps, OS swap | Prefer **temporary creds** so a leaked dump expires in hours |
| Server holds creds at all | **Local-agent mode** (post-1.0): discovery runs on the user's machine, posts only the Graph |
| Key in transit | POST body over TLS only — never URL (logged), never localStorage |

Structural moves:
- **Push toward STS / assume-role + ExternalId, or pasted session tokens.**
  Auto-expiry bounds blast radius. Offer "generate the assume-role command."
- **Local-agent ingestion mode** (post-1.0): same adapter code runs as a CLI on
  the user's machine and POSTs only the resulting `Graph`; the persistent
  server never touches a key. Cleanest possible credential story.
- **Least-privilege read-only policy is derived** from exactly the API calls the
  adapters + assume-role analysis make: baseline `SecurityAudit` +
  `ViewOnlyAccess` + `GetAccountAuthorizationDetails` + Access Analyzer read,
  and **deliberately excludes** `secretsmanager:GetSecretValue` /
  `ssm:GetParameter` (decrypt). "It cannot read your secrets" becomes a
  compile-time guarantee, not a promise.

### (B) Secrets we *discover* in the environment (the sleeper issue)

Even after discarding the operator's key, discovery collects secret material
that hides in: Lambda/ECS task-def **env vars**, EC2 **user-data**, plaintext
secrets in **tags**, and Secrets Manager / SSM **SecureString** parameters.

Rules:
- **Never resolve secret values.** List a Secrets Manager secret / SSM
  SecureString as a **node** (ARN + metadata) — never call `GetSecretValue`.
  Made *provably impossible* by omitting the permission from the least-priv
  policy.
- **Sanitization layer at the adapter→graph boundary:** entropy + regex
  detection (`AKIA…`, `-----BEGIN … KEY-----`, etc.) on user-data/env vars →
  store `{ secretPresent: true, kind: 'aws-key' }`, **not the value**.
- This flips a risk into a **feature:** "plaintext secret detected in user-data"
  is a surfaced `Finding`.
- Offer a **redacted export mode**. Exported `.json` maps are confidential.

### The unifying insight

**The IAM lens turns discovered secrets into first-class target nodes.**
"Who can read SecretX?" is just a reverse-reachability query against a secret
node. The signature view (deferred, post the assume-role MVP):

> Click a Secrets Manager secret → highlight **every principal, including every
> *external* principal, that can reach it** — each edge labeled by how (direct
> read vs escalation vs cross-account trust).

Secret-sprawl + access-exposure + IAM reachability in one picture. Secrets
aren't a separate subsystem — **they're the highest-value targets in the
reachability graph.**

---

## 7. Why it will look good (Cytoscape specifics)

- **Compound nodes** for `account → region → VPC → AZ → subnet → resource`.
- **Layout:** `cytoscape-elk` (layered) for clean left-to-right "traffic flows
  this way"; `fcose` fallback for non-hierarchical bits.
- **`cytoscape-expand-collapse`** for semantic zoom — collapse a VPC to one box
  when zoomed out.
- Official AWS resource icons, per-lens edge colors, edge bundling to kill
  hairballs.
- Path highlighting for IAM reachability queries — where Cytoscape shines and
  PMapper's dot output looks academic.

---

## 8. Milestones

1. **Normalized graph schema** — `@kumomiru/graph` with types (incl. `Finding`
   and `lens:'iam'`), Zod schema, and a hand-authored sample graph exercising
   all three lenses + a secret finding. The spine everything hangs off.
2. **Terraform-state adapter** — zero creds = fast, safe demo → real graph out.
3. **Backend** — Fastify serves graph JSON + frontend shell.
4. **Cytoscape viewer** — containment + ELK layout + **network lens only**.
   ← first "whoa" moment.
5. **Live AWS adapter** (EC2/VPC/IAM/ELB/RDS/S3/Lambda) — ships *with* the
   credential broker (A) and sanitization layer (B); they are how discovery is
   allowed to touch creds at all.
6. **IAM + dataflow lenses** + the lens toggle. IAM scoped to **assume-role
   only**; Access Analyzer + escalation taxonomy are later increments.
7. **Polish** — collapse/expand, search, filter, PNG/JSON export, redacted
   export mode.

---

## 9. Prior art (don't reinvent)

Cartography (graph in Neo4j), CloudMapper, Steampipe (SQL over cloud APIs),
Cloudquery, AWS Perspective, Terraform `terraform graph`, PMapper (IAM
reachability, BSD), Cloudsplaining/parliament (policy linting), AWS IAM Access
Analyzer. The gap they leave: **good interactive visualization.** That gap is
the product.
