# kumomiru — planned improvements & features

Concrete, repo-specific work items derived from a full read of the codebase and
the "Recommended next" list in `IMPROVEMENTS.md`. Weighted toward correctness of
the two flagship exposures (internet ingress, external-can-assume), adapter
parity (Terraform should feed the same shared "brain" the live adapter does),
and the visualization/ease-of-use thesis (DESIGN.md §1).

## Improvements (existing behavior / robustness / perf / UX / tests)

1. **Paginate every live SDK list call.** EC2 `Describe*`, `DescribeDBInstances`,
   `ListFunctions`, `ListSecrets` only read the first page today, so large
   accounts produce a silently incomplete map. Add NextToken/Marker loops.
   *(server `aws/sdkClient.ts`)*
2. **Drop the Lambda `GetFunctionConfiguration` N+1.** `ListFunctions` already
   returns each function's `Environment`; fetching per-function is a redundant
   call *and* an extra permission. Remove it and shrink the least-privilege set.
   *(server `aws/sdkClient.ts`, `docs/least-privilege-policy.json`)*
3. **Fix the live internet-facing ingress edge.** It self-loops instance→itself
   when the SG node lookup misses and hardcodes `from: 0.0.0.0/0` even for an
   IPv6 `::/0` rule. Always source from the SG and carry the real CIDR.
   *(adapters `aws-live/discover.ts`)*
4. **Scan tags for plaintext secrets in the live adapter.** The Terraform adapter
   already scans (and redacts) tag values; live discovery does not, so a secret
   in a live tag ships unflagged. Add parity. *(adapters `aws-live/discover.ts`)*
5. **First-class `aws::iam::user` in the viewer.** Live discovery emits user
   nodes that currently render as anonymous white boxes: no glyph, no accent, no
   humanized label. Add all three. *(viewer `lib/icons.ts`, `lib/style.ts`,
   `lib/format.ts`)*
6. **React error boundary.** A Cytoscape/render throw currently blanks the whole
   app. Wrap it so failures show a recoverable message. *(viewer new
   `components/ErrorBoundary.tsx`, `main.tsx`)*
7. **Keyboard / a11y.** Escape closes the Load-data modal and the inspector; the
   modal takes focus on open. *(viewer `DataSourcePanel.tsx`, `App.tsx`)*
8. **Findings severity summary.** Show per-severity counts atop the findings
   list so risk is legible at a glance. *(viewer `FindingsPanel.tsx`)*
9. **Tighten Lambda-env → resource dataflow inference.** Matching is bare
   substring today, so a short RDS identifier can fabricate a `connects-to`
   edge. Require a delimited/host-style match. *(adapters `aws-live/discover.ts`)*
10. **Harden the spine validator.** `checkReferentialIntegrity` misses self-loop
    edges and duplicate finding ids. Flag both, with tests. *(graph
    `validate.ts`, `graph.test.ts`)*

## New features

11. **Terraform IAM lens.** Parse `assume_role_policy` (trust) + inline identity
    policies and `aws_iam_user` from state and run the shared `analyzeAssumeRole`
    brain, so tfstate maps get `can-assume` edges and external-can-assume
    findings — the parity the design calls for (IAM is an analysis pass, not an
    adapter). *(adapters new `terraform/iam.ts`, `terraform/mappings.ts`,
    `terraform/index.ts`, tests)*
12. **Terraform dataflow + internet exposure.** Parse security-group ingress
    (SG-to-SG and `0.0.0.0/0`) from state to emit dataflow `talks-to` edges and
    network internet-facing edges, matching the live adapter.
    *(adapters `terraform/index.ts`, tests)*
13. **Server-side redacted maps.** `?redacted=1` on `/sample`, `/map/terraform`,
    and `/map/live` returns the topology with data values stripped via the shared
    `redactGraph` — DESIGN §6B's server-side redacted export. *(server
    `routes`, `app.ts`, tests)*
14. **Forward IAM reachability.** "What can this reach?" complements the existing
    reverse "Who can reach this?" (DESIGN §5 lists both). *(viewer
    `lib/reachability.ts`, `App.tsx`, `InspectorPanel.tsx`)*
15. **Least-privilege policy endpoint + one-click download.** `GET
    /policy/least-privilege` serves the exact read-only action set the adapters
    use (single source of truth); the viewer's Live tab downloads it so onboarding
    a scan role is trivial. *(server new `routes/policy.ts`, viewer
    `lib/api.ts`, `DataSourcePanel.tsx`)*
