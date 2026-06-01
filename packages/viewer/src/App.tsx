import { useEffect, useState } from "react";
import type { Graph, Lens } from "@kumomiru/graph";

import { fetchSample } from "./lib/api.js";
import { availableLenses } from "./lib/elements.js";
import { GraphView } from "./components/GraphView.js";
import { LensToggle } from "./components/LensToggle.js";
import { FindingsPanel } from "./components/FindingsPanel.js";

export function App() {
  const [graph, setGraph] = useState<Graph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lens, setLens] = useState<Lens>("network");

  useEffect(() => {
    fetchSample()
      .then(setGraph)
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  }, []);

  if (error) {
    return (
      <div className="app-state">
        <h1>kumomiru</h1>
        <p className="error">Could not load graph: {error}</p>
        <p className="hint">
          Is the server running? <code>pnpm --filter @kumomiru/server dev</code>
        </p>
      </div>
    );
  }

  if (!graph) {
    return (
      <div className="app-state">
        <h1>kumomiru</h1>
        <p>Loading…</p>
      </div>
    );
  }

  const lenses = availableLenses(graph);

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">kumomiru</span>
        <LensToggle lenses={lenses} active={lens} onChange={setLens} />
        <span className="meta">
          {graph.nodes.length} nodes · {graph.edges.length} edges ·{" "}
          {graph.meta.source}
        </span>
      </header>
      <div className="body">
        <GraphView graph={graph} lens={lens} />
        <aside className="sidebar">
          <h2>Findings</h2>
          <FindingsPanel findings={graph.findings} />
        </aside>
      </div>
    </div>
  );
}
