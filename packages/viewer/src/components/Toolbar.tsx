import type { Core } from "cytoscape";
import type { Graph } from "@kumomiru/graph";

import { exportPng, exportJson } from "../lib/export.js";

interface ToolbarProps {
  graph: Graph;
  /** Returns the live Cytoscape instance, or null before it has mounted. */
  getCy: () => Core | null;
}

/** Right-aligned actions: export the map as PNG or (optionally redacted) JSON. */
export function Toolbar({ graph, getCy }: ToolbarProps) {
  const onPng = () => {
    const cy = getCy();
    if (cy) exportPng(cy);
  };

  return (
    <div className="toolbar">
      <button type="button" onClick={onPng} title="Export the canvas as a PNG">
        PNG
      </button>
      <button
        type="button"
        onClick={() => exportJson(graph, false)}
        title="Export the full graph as JSON"
      >
        JSON
      </button>
      <button
        type="button"
        onClick={() => exportJson(graph, true)}
        title="Export JSON with data values stripped (safe to share)"
      >
        Redacted JSON
      </button>
    </div>
  );
}
