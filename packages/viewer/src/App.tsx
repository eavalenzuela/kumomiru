import { useCallback, useEffect, useRef, useState } from "react";
import type { Core } from "cytoscape";
import type { Graph, Lens } from "@kumomiru/graph";

import { fetchSample } from "./lib/api.js";
import { availableLenses } from "./lib/elements.js";
import { GraphView } from "./components/GraphView.js";
import { LensToggle } from "./components/LensToggle.js";
import { FindingsPanel } from "./components/FindingsPanel.js";
import { Toolbar } from "./components/Toolbar.js";
import { SearchBox } from "./components/SearchBox.js";
import { applySearch } from "./lib/search.js";

export function App() {
  const [graph, setGraph] = useState<Graph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lens, setLens] = useState<Lens>("network");

  // The live Cytoscape instance, shared with the toolbar (PNG export, etc.).
  // A ref (not state) so capturing it does not trigger a re-render/rebuild.
  const cyRef = useRef<Core | null>(null);
  const onCyReady = useCallback((cy: Core | null) => {
    cyRef.current = cy;
  }, []);
  const getCy = useCallback(() => cyRef.current, []);

  const [query, setQuery] = useState("");
  const [matches, setMatches] = useState(0);

  useEffect(() => {
    fetchSample()
      .then(setGraph)
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  }, []);

  // Apply the search highlight whenever the query or the loaded graph changes.
  // GraphView's build effect runs first (child effects fire before parent), so
  // the Cytoscape instance exists by the time this runs.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    setMatches(applySearch(cy, query));
  }, [query, graph]);

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
        <SearchBox value={query} onChange={setQuery} matches={matches} />
        <div className="topbar-right">
          <span className="meta">
            {graph.nodes.length} nodes · {graph.edges.length} edges ·{" "}
            {graph.meta.source}
          </span>
          <Toolbar graph={graph} getCy={getCy} />
        </div>
      </header>
      <div className="body">
        <GraphView graph={graph} lens={lens} onCyReady={onCyReady} />
        <aside className="sidebar">
          <h2>Findings</h2>
          <FindingsPanel findings={graph.findings} />
        </aside>
      </div>
    </div>
  );
}
