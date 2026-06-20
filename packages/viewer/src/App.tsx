import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Core } from "cytoscape";
import type { Graph, Lens } from "@kumomiru/graph";

import { fetchSample } from "./lib/api.js";
import { availableLenses } from "./lib/elements.js";
import { GraphView } from "./components/GraphView.js";
import { LensToggle } from "./components/LensToggle.js";
import { FindingsPanel } from "./components/FindingsPanel.js";
import { InspectorPanel, type Connection } from "./components/InspectorPanel.js";
import { Toolbar } from "./components/Toolbar.js";
import { SearchBox } from "./components/SearchBox.js";
import { Legend } from "./components/Legend.js";
import { MapControls } from "./components/MapControls.js";
import { DataSourcePanel } from "./components/DataSourcePanel.js";
import { applySearch } from "./lib/search.js";
import { reverseReachable } from "./lib/reachability.js";

const EXTERNAL_PRINCIPAL_TYPE = "aws::iam::external-principal";

export function App() {
  const [graph, setGraph] = useState<Graph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lens, setLens] = useState<Lens>("network");
  const [selected, setSelected] = useState<string | null>(null);
  const [traceId, setTraceId] = useState<string | null>(null);
  const [dataSourceOpen, setDataSourceOpen] = useState(false);

  // Selecting a node clears any active reachability trace.
  const selectNode = useCallback((id: string | null) => {
    setSelected(id);
    setTraceId(null);
  }, []);
  // "Who can reach this?" — the trace is an IAM-lens question, so switch to it.
  const traceNode = useCallback((id: string) => {
    setLens("iam");
    setSelected(id);
    setTraceId(id);
  }, []);

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

  // When a new graph loads, clear stale selection and make sure the active lens
  // actually exists in it (a graph with no network edges must not open on an
  // empty 'network' view).
  const lenses = useMemo(() => (graph ? availableLenses(graph) : []), [graph]);
  useEffect(() => {
    setSelected(null);
    setTraceId(null);
    if (lenses.length > 0 && !lenses.includes(lens)) setLens(lenses[0]!);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph]);

  // The reachability spotlight: which principals can reach the traced node.
  const trace = useMemo(
    () => (traceId && graph ? reverseReachable(graph, traceId, "iam") : null),
    [graph, traceId],
  );

  // Apply the search highlight whenever the query or the loaded graph changes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    setMatches(applySearch(cy, query));
  }, [query, graph]);

  // Resolve the selected node and everything the inspector needs from the graph
  // model (never from a cloud SDK).
  const nodeById = useMemo(
    () => new Map((graph?.nodes ?? []).map((n) => [n.id, n])),
    [graph],
  );
  const selectedNode = selected ? (nodeById.get(selected) ?? null) : null;
  const tracedNode = traceId ? (nodeById.get(traceId) ?? null) : null;
  const selectedFindings = useMemo(
    () =>
      selected ? (graph?.findings ?? []).filter((f) => f.nodeId === selected) : [],
    [graph, selected],
  );
  const connections = useMemo<Connection[]>(() => {
    if (!selected || !graph) return [];
    const out: Connection[] = [];
    for (const e of graph.edges) {
      const isSource = e.source === selected;
      const isTarget = e.target === selected;
      if (!isSource && !isTarget) continue;
      const otherId = isSource ? e.target : e.source;
      const attrs = e.attributes ?? {};
      const danger =
        attrs["internetFacing"] === true ||
        nodeById.get(e.source)?.type === EXTERNAL_PRINCIPAL_TYPE;
      out.push({
        dir: isSource ? "out" : "in",
        relationship: e.relationship,
        lens: e.lens,
        otherId,
        otherName: nodeById.get(otherId)?.name || otherId,
        danger,
      });
    }
    return out;
  }, [graph, selected, nodeById]);

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

  const shownEdges = graph.edges.filter((e) => e.lens === lens).length;

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">kumomiru</span>
        <LensToggle lenses={lenses} active={lens} onChange={setLens} />
        <SearchBox value={query} onChange={setQuery} matches={matches} />
        <div className="topbar-right">
          <span className="meta">
            {graph.nodes.length} nodes · {shownEdges}/{graph.edges.length} edges
            in {lens} · {graph.meta.source}
          </span>
          <button
            type="button"
            className="load-data-btn"
            onClick={() => setDataSourceOpen(true)}
          >
            Load data
          </button>
          <Toolbar graph={graph} getCy={getCy} />
        </div>
      </header>
      {dataSourceOpen && (
        <DataSourcePanel
          onClose={() => setDataSourceOpen(false)}
          onLoad={(g) => {
            setGraph(g);
            setDataSourceOpen(false);
          }}
        />
      )}
      <div className="body">
        <div className="canvas-wrap">
          <GraphView
            graph={graph}
            lens={lens}
            selectedId={selected}
            trace={trace}
            onSelect={selectNode}
            onCyReady={onCyReady}
          />
          {trace && tracedNode && (
            <div className="trace-banner">
              <span>
                <strong>{Math.max(trace.nodes.length - 1, 0)}</strong> principal
                {trace.nodes.length - 1 === 1 ? "" : "s"} can reach{" "}
                <strong>{tracedNode.name || tracedNode.id}</strong>
              </span>
              <button type="button" onClick={() => setTraceId(null)}>
                Clear
              </button>
            </div>
          )}
          <Legend lens={lens} />
          <MapControls getCy={getCy} />
        </div>
        <aside className="sidebar">
          {selectedNode ? (
            <InspectorPanel
              node={selectedNode}
              findings={selectedFindings}
              connections={connections}
              onSelectNode={selectNode}
              onTrace={traceNode}
              onClose={() => selectNode(null)}
            />
          ) : (
            <>
              <h2>Findings</h2>
              <FindingsPanel findings={graph.findings} onSelect={selectNode} />
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
