# kumomiru — value-adding improvements

Analysis of the tool against its own thesis (DESIGN.md §1: *the differentiator
is visualization quality and ease of use*), then an implementation pass. UI
changes were verified by driving a live instance with a headless browser and
inspecting screenshots; backend changes are covered by tests (`pnpm -r test` —
59 passing).

The candidate list was produced by reading the whole codebase plus a multi-agent
review, then deduplicated and prioritized by value-to-effort, weighted toward the
visualization (the product) and toward security correctness (the two flagship
findings).

## Implemented

### Visualization — "reads like an architecture diagram"
- **Resource glyphs on every leaf node** (`viewer/src/lib/icons.ts`): inline-SVG
  icons per AWS type (EC2, RDS, Lambda, DynamoDB, secret, IAM role, external
  principal, IGW, security group), tinted to the type accent. Was plain bordered
  rectangles.
- **Fixed off-lens "ghost boxes"**: off-lens leaves were dimmed to 8% opacity
  with hidden labels, reading as rendering artifacts. Now the shared node set is
  kept stable across lenses and off-lens leaves render as clean *muted context*;
  only off-lens edges are hidden.
- **Per-lens & exposure edge styling** (`lib/style.ts`): network = slate,
  IAM = violet, dataflow = cyan dashed; **internet-facing ingress and
  external-principal access are bold red in every lens** — the two exposures the
  tool exists to surface.
- **Security findings on the canvas**: a node that is the subject of a
  critical/high finding now wears a red/orange danger halo, so the risk is
  visible on the map, not buried in the sidebar.
- **Active-lens legend** (`components/Legend.tsx`) and **map controls**
  (`components/MapControls.tsx`: zoom / fit / collapse-all).

### Interaction
- **Node selection + inspector panel** (`components/InspectorPanel.tsx`): the
  `onSelect` plumbing existed but was never wired in `App.tsx` — clicking did
  nothing. Now tapping a node (or a finding) opens a detail panel: type, ARN,
  findings, sanitized attributes/tags, and clickable connections. Selecting also
  highlights the node's neighborhood.
- **Click a finding → focus its node** (camera centers, inspector opens).
- **Fixed the silently-broken collapse/expand**: a collapsed compound lost its
  centroid and rendered nowhere. Collapse now detaches children so the container
  draws as a proper chip (semantic zoom, DESIGN §7). Double-click one container,
  or collapse-all from the toolbar.
- Per-active-lens edge counts in the header; a valid default lens on load;
  `ResizeObserver` so the canvas tracks layout changes; unified tap handler and
  callback refs (no full rebuild on every keystroke).

### Signature feature — IAM reachability (DESIGN §6)
- **"Who can reach this?"** (`lib/reachability.ts`): from the inspector, spotlight
  every principal that can reach the selected node over IAM edges (reverse
  transitive closure) — e.g. a Secrets Manager secret lights up the role that can
  read it *and* the principal that can assume that role. Pure topology; never
  resolves a secret value.

### Data ingestion
- **Load your own data** (`components/DataSourcePanel.tsx`): the viewer only ever
  loaded `/sample`. Now a modal exposes the two existing server paths — Terraform
  state (upload or paste) and live read-only AWS discovery. Credentials stay in
  the POST body, are never persisted, and the form clears on resolve.

### Security & correctness (backend, with tests)
- **Secret detection** (`adapters/.../sanitize.ts`): the generic detector
  required quotes around the value and silently missed the most common case —
  bare env vars like `DB_PASSWORD=hunter2supersecret`. Fixed, plus high-signal
  detectors (GitHub/Slack/Stripe tokens, Google API keys, URL credentials).
- **IAM external-principal false positives** (`adapters/.../analysis/iam.ts`):
  same-account `sts:assumed-role` sessions and GovCloud/China partition ARNs were
  flagged external, fabricating *critical* findings. ARN account extraction is now
  partition- and service-agnostic.
- **Terraform adapter now runs secret scanning** (`adapters/.../terraform`):
  tfstate previously produced zero findings; it now scans user-data, Lambda env
  vars, and tag values, marks (never stores) the value, and raises findings.
- **Credential leak in live-route error logging** (`server/.../routes/live.ts`):
  SDK errors were logged whole; the existing `redactObject` had no call sites.
  Errors are now scrubbed before logging.
- **`redactGraph` denylist → allowlist** (`graph/src/redact.ts`): a 3-key denylist
  leaked any new value-bearing attribute. Redaction now keeps only secret markers,
  numbers/booleans, and an allowlist of structural keys.

## Recommended next (not yet implemented)
- SDK list calls are unpaginated except auth-details — large environments yield
  silently incomplete maps (`server/.../aws/sdkClient.ts`).
- Live network pass: internet-facing edge self-loops on a missing SG node and
  hardcodes `0.0.0.0/0`; dataflow env-ref resolution uses substring matching
  (`adapters/.../aws-live/discover.ts`).
- Full Terraform parity: IAM (parse `assume_role_policy`) and dataflow passes.
- Tag scanning in the live adapter; orthogonal (taxi) edge routing; a dark "ops"
  theme; a server-side redacted-map endpoint; keyboard navigation.
