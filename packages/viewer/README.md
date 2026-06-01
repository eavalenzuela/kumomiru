# @kumomiru/viewer

The interactive map. A Vite + React app that renders the normalized
[`@kumomiru/graph`](../graph) with Cytoscape.js — the part of kumomiru that
justifies the whole project (existing tools are query-heavy and ugly; this is
the nice visual layer).

## What it does

- Fetches a graph (currently `GET /sample` via the dev proxy) and validates it
  through the **shared schema** before rendering — same schema the server
  produced it with, so drift fails loudly.
- Renders **compound nodes** for containment
  (`account → region → VPC → subnet → resource`) so the map reads like an
  architecture diagram, laid out with **ELK layered** (`cytoscape-elk`) for the
  directional "traffic flows this way" look.
- **Lens toggle** (Network / IAM / Data flow): switching dims edges (and newly
  isolated leaf nodes) outside the active lens; containers stay lit so structure
  never collapses. Network is the default and emphasizes **internet-facing
  ingress in red**.
- A **Findings** sidebar lists security findings, most severe first.

## Run

The viewer needs the server for data:

```sh
pnpm --filter @kumomiru/server dev     # serves GET /sample on :4000
pnpm --filter @kumomiru/viewer dev     # Vite on :5173, proxies /api -> :4000
```

Then open http://localhost:5173.

## Build / typecheck

```sh
pnpm --filter @kumomiru/viewer typecheck
pnpm --filter @kumomiru/viewer build
```

## Layout of the code

| Path | Role |
|---|---|
| `src/lib/elements.ts` | `Graph` → Cytoscape elements (containment → `parent`, lens on edges). |
| `src/lib/style.ts` | Stylesheet — container tints, per-type accents, internet-facing emphasis, `.dimmed`. |
| `src/lib/layout.ts` | ELK layered layout options. |
| `src/lib/api.ts` | Fetch + schema-validate graphs. |
| `src/components/GraphView.tsx` | The Cytoscape canvas; reacts to lens changes without rebuilding. |
| `src/components/LensToggle.tsx` | Segmented lens control. |
| `src/components/FindingsPanel.tsx` | Severity-sorted findings list. |
