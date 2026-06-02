import type { Core } from "cytoscape";
import type { Graph } from "@kumomiru/graph";
import { redactGraph } from "@kumomiru/graph";

/**
 * Browser-side export helpers. The map and its JSON are confidential
 * (DESIGN.md §6B), so JSON export offers a redacted mode that strips data
 * values while preserving topology — backed by the same `redactGraph` the
 * server can use, so "redacted" means the same thing everywhere.
 */

/** Trigger a browser download of a Blob under the given filename. */
function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next tick so the click has a chance to start the download.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Export the current canvas as a high-resolution PNG. */
export function exportPng(cy: Core, filename = "kumomiru-map.png"): void {
  const blob = cy.png({ output: "blob", full: true, scale: 2, bg: "#ffffff" });
  downloadBlob(blob as Blob, filename);
}

/** Export the graph as JSON; `redacted` strips data values for safe sharing. */
export function exportJson(
  graph: Graph,
  redacted: boolean,
  filename = redacted ? "kumomiru-map.redacted.json" : "kumomiru-map.json",
): void {
  const out = redacted ? redactGraph(graph) : graph;
  const blob = new Blob([JSON.stringify(out, null, 2)], {
    type: "application/json",
  });
  downloadBlob(blob, filename);
}
