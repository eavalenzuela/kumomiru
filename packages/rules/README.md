# @kumomiru/rules

The posture rule engine. A rule is a typed TypeScript function over the
normalized `Graph` — no Rego, no DSL — registered with a stable id, severity,
the framework controls it satisfies, and remediation guidance the operator
runs themselves.

| File | Role |
|---|---|
| `types.ts` | `Rule`, `RuleContext`, `RuleOutcome`. |
| `registry.ts` | Id-unique registry; `defaultRegistry()` holds every built-in rule. |
| `run.ts` | `evaluate(graph, registry, { capabilities })` → per-resource `RuleResult`s + `Finding`s with deterministic ids. |
| `compliance.ts` | Per-control roll-up (`ControlStatus[]`) for a framework. |
| `frameworks/` | Control catalogues: AWS FSBP and NIST CSF 2.0. Authored in-house and versioned. |
| `checks/` | The rules, grouped by service. `native.ts` adopts the findings the adapters already emit. |

## Rule semantics

- A rule declares `requires` (collector capabilities, e.g. `ec2:security-group`).
  If the graph was produced without one of them, every applicable resource is
  `not-assessed` — never `pass`.
- Finding ids are `f-<ruleId>-<djb2(resourceId)>`, so the same problem on the
  same resource has the same id across snapshots. That is what lets the
  lifecycle layer tell "still open" from "new". A renamed rule declares
  `replaces: [oldId]`.
- Findings the adapters emit themselves (`plaintext-secret`,
  `external-can-assume`) are *adopted*: their control mapping and remediation
  live here, the detection stays where it is.
