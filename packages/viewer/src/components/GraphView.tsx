import { useEffect, useRef } from "react";
import cytoscape, { type Core } from "cytoscape";
import type { Graph, Lens } from "@kumomiru/graph";

import { ensureCytoscapeExtensions } from "../lib/cytoscapeSetup.js";
import { graphToElements } from "../lib/elements.js";
import { buildStylesheet } from "../lib/style.js";
import { elkLayout } from "../lib/layout.js";

ensureCytoscapeExtensions();

interface GraphViewProps {
  graph: Graph;
  lens: Lens;
  onSelect?: (id: string | null) => void;
  /** Called with the Cytoscape instance once built (and null on teardown). */
  onCyReady?: (cy: Core | null) => void;
}

/**
 * Dim everything outside the active lens; containers always stay lit so the
 * structural frame never collapses. A leaf node with no edge in the active lens
 * is dimmed along with its edges.
 */
function applyLens(cy: Core, lens: Lens): void {
  cy.batch(() => {
    cy.edges().forEach((edge) => {
      edge.toggleClass("dimmed", edge.data("lens") !== lens);
    });
    cy.nodes().forEach((node) => {
      if (node.data("container")) {
        node.removeClass("dimmed");
        return;
      }
      const hasActiveEdge = node
        .connectedEdges()
        .some((e) => e.data("lens") === lens);
      node.toggleClass("dimmed", !hasActiveEdge);
    });
  });
}

/**
 * The Cytoscape canvas. Builds the instance once per graph and applies the
 * active lens as part of that same build, so the initial filter can never be
 * lost to effect ordering or an extension's init. Lens *changes* are handled by
 * a lightweight second effect that re-runs the same filter without rebuilding.
 */
export function GraphView({ graph, lens, onSelect, onCyReady }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  // Track the latest lens so the build effect can apply it without depending on
  // `lens` (depending on it would rebuild the whole graph on every toggle).
  const lensRef = useRef(lens);
  lensRef.current = lens;

  // Build / rebuild when the graph identity changes.
  useEffect(() => {
    if (!containerRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      elements: graphToElements(graph),
      style: buildStylesheet(),
      layout: elkLayout(),
      wheelSensitivity: 0.2,
    });
    cyRef.current = cy;
    onCyReady?.(cy);

    // Semantic zoom: double-click a compound container to collapse it (and
    // again to expand). Hand-rolled with Cytoscape core only — collapsing just
    // hides the descendants and lets the compound parent shrink to a chip.
    // (cytoscape-expand-collapse is incompatible with this Cytoscape version —
    // it throws inside its own collapse path — so we don't use it.)
    // Cytoscape has no native double-click, so we detect a quick second tap.
    let lastTapId = "";
    let lastTapAt = 0;
    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      const now = Date.now();
      const isDouble = node.id() === lastTapId && now - lastTapAt < 350;
      lastTapId = node.id();
      lastTapAt = now;
      if (!isDouble || !node.isParent()) return; // only containers collapse
      const collapsing = !node.hasClass("collapsed");
      cy.batch(() => {
        node.toggleClass("collapsed", collapsing);
        node.descendants().toggleClass("collapsed-hidden", collapsing);
      });
    });

    // Apply the active lens now, and once more after ELK settles, so the filter
    // survives both effect-ordering and any class churn during layout.
    applyLens(cy, lensRef.current);
    cy.one("layoutstop", () => applyLens(cy, lensRef.current));

    if (onSelect) {
      cy.on("tap", "node", (evt) => onSelect(evt.target.id()));
      cy.on("tap", (evt) => {
        if (evt.target === cy) onSelect(null);
      });
    }

    return () => {
      onCyReady?.(null);
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, onSelect, onCyReady]);

  // React to lens changes without rebuilding the whole graph.
  useEffect(() => {
    const cy = cyRef.current;
    if (cy) applyLens(cy, lens);
  }, [lens]);

  return <div ref={containerRef} className="graph-canvas" />;
}
