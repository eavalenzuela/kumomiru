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
}

/**
 * The Cytoscape canvas. Builds the instance once per graph, then reacts to lens
 * changes by dimming edges (and nodes that become isolated) outside the active
 * lens — containers always stay visible so the structure never collapses.
 */
export function GraphView({ graph, lens, onSelect }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

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

    if (onSelect) {
      cy.on("tap", "node", (evt) => onSelect(evt.target.id()));
      cy.on("tap", (evt) => {
        if (evt.target === cy) onSelect(null);
      });
    }

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, onSelect]);

  // React to lens changes without rebuilding the whole graph.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.edges().forEach((edge) => {
        const active = edge.data("lens") === lens;
        edge.toggleClass("dimmed", !active);
      });
      // A leaf node with no active (non-dimmed) edge gets dimmed too; containers
      // and nodes still touched by the active lens stay lit.
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
  }, [lens]);

  return <div ref={containerRef} className="graph-canvas" />;
}
