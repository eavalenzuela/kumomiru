import { useEffect, useRef } from "react";
import cytoscape, { type Core } from "cytoscape";
import type { Graph, Lens } from "@kumomiru/graph";

import { ensureCytoscapeExtensions } from "../lib/cytoscapeSetup.js";
import { graphToElements } from "../lib/elements.js";
import { buildStylesheet } from "../lib/style.js";
import { elkLayout } from "../lib/layout.js";
import { toggleCollapse } from "../lib/collapse.js";

ensureCytoscapeExtensions();

interface GraphViewProps {
  graph: Graph;
  lens: Lens;
  /** The currently selected node id (drives the canvas highlight). */
  selectedId?: string | null;
  /** Reverse-reachability set to spotlight ("who can reach this?"), or null. */
  trace?: { nodes: string[]; edges: string[] } | null;
  /** Fired on node tap (id) and on background tap (null). */
  onSelect?: (id: string | null) => void;
  /** Called with the Cytoscape instance once built (and null on teardown). */
  onCyReady?: (cy: Core | null) => void;
}

/**
 * Apply the active lens. The node set is shared across all three lenses (the
 * core idea in DESIGN.md §4), so we never add or remove nodes — toggling a lens
 * keeps the map perfectly stable and comparable, and the initial fit stays
 * valid. Instead:
 *
 *   - edges not in the active lens are hidden, so only the relationships that
 *     lens is about are drawn (no cross-lens clutter);
 *   - a leaf resource with no edge in the active lens is *muted* (recessed, but
 *     still legible) so it reads as context rather than disappearing — and
 *     crucially not as a faint empty "ghost box" (the old behaviour dimmed to 8%
 *     opacity with the label hidden, which looked like a rendering artifact);
 *   - containers are never muted: they are the structural frame.
 */
function applyLens(cy: Core, lens: Lens): void {
  cy.batch(() => {
    cy.edges().forEach((edge) => {
      edge.toggleClass("lens-off", edge.data("lens") !== lens);
    });
    cy.nodes()
      .filter((n) => !n.data("container"))
      .forEach((node) => {
        const inLens = node
          .connectedEdges()
          .some((e) => e.data("lens") === lens);
        node.toggleClass("lens-muted", !inLens);
      });
  });
}

/**
 * Highlight the selected node and its immediate neighborhood ("what does this
 * touch?"). Emphasis only — we never fade the rest, so this composes cleanly
 * with the lens-muting and search classes instead of fighting them over opacity.
 */
function highlightSelection(cy: Core, id: string | null): void {
  cy.batch(() => {
    cy.elements().removeClass("sel sel-adj");
    if (!id) return;
    const node = cy.$id(id);
    if (node.empty()) return;
    node.addClass("sel");
    const edges = node.connectedEdges();
    edges.addClass("sel-adj");
    edges.connectedNodes().not(node).addClass("sel-adj");
  });
}

/**
 * Spotlight a reverse-reachability set: everything that can reach the target
 * stays lit and is ringed, everything else is faded (containers stay so the
 * frame survives). Passing null clears it.
 */
function applyTrace(
  cy: Core,
  trace: { nodes: string[]; edges: string[] } | null,
): void {
  cy.batch(() => {
    cy.elements().removeClass("trace trace-faded");
    if (!trace) return;
    cy.elements().not("[?container]").addClass("trace-faded");
    for (const id of trace.nodes) cy.$id(id).removeClass("trace-faded").addClass("trace");
    for (const id of trace.edges) cy.$id(id).removeClass("trace-faded").addClass("trace");
  });
}

/**
 * The Cytoscape canvas. Builds the instance once per graph and applies the
 * active lens as part of that same build, so the initial filter can never be
 * lost to effect ordering or an extension's init. Lens, selection, and resize
 * are handled by lightweight follow-up effects that never rebuild — callbacks
 * are read through refs so their identity can't trigger a teardown.
 */
export function GraphView({
  graph,
  lens,
  selectedId = null,
  trace = null,
  onSelect,
  onCyReady,
}: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // Keep mutable mirrors of props the build effect must read but not depend on,
  // so rebuilding only happens when the graph itself changes.
  const lensRef = useRef(lens);
  lensRef.current = lens;
  const selectedRef = useRef(selectedId);
  selectedRef.current = selectedId;
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const onCyReadyRef = useRef(onCyReady);
  onCyReadyRef.current = onCyReady;
  // The last id the user tapped, so a programmatic selection (e.g. clicking a
  // finding) re-centers the camera but a direct tap does not jump the view.
  const lastTapRef = useRef<string | null>(null);

  // Build / rebuild only when the graph identity changes.
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
    onCyReadyRef.current?.(cy);
    // Dev convenience: expose the instance for screenshot/debug harnesses.
    if ((import.meta as { env?: { DEV?: boolean } }).env?.DEV) {
      (window as unknown as { __cy?: Core }).__cy = cy;
    }

    // One tap handler for nodes: a quick second tap on a container collapses it
    // (semantic zoom — Cytoscape has no native double-click), and every tap also
    // selects. Unified so collapse and select can't fight as two listeners.
    // (cytoscape-expand-collapse is incompatible with this Cytoscape version —
    // it throws inside its own collapse path — so collapse is hand-rolled.)
    let lastTapId = "";
    let lastTapAt = 0;
    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      const now = Date.now();
      const isDouble = node.id() === lastTapId && now - lastTapAt < 350;
      lastTapId = node.id();
      lastTapAt = now;
      if (isDouble && node.isParent()) toggleCollapse(node);
      lastTapRef.current = node.id();
      onSelectRef.current?.(node.id());
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) onSelectRef.current?.(null);
    });

    // Apply lens + any existing selection now, and once more after ELK settles,
    // so they survive both effect-ordering and class churn during layout.
    const settle = () => {
      applyLens(cy, lensRef.current);
      highlightSelection(cy, selectedRef.current);
    };
    settle();
    cy.one("layoutstop", settle);

    return () => {
      onCyReadyRef.current?.(null);
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph]);

  // React to lens changes without rebuilding the whole graph.
  useEffect(() => {
    const cy = cyRef.current;
    if (cy) applyLens(cy, lens);
  }, [lens]);

  // React to selection changes: highlight the neighborhood, and re-center the
  // camera only when the selection was made programmatically (e.g. a finding).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    highlightSelection(cy, selectedId);
    if (selectedId && selectedId !== lastTapRef.current) {
      const node = cy.$id(selectedId);
      if (node.nonempty()) {
        cy.animate({ center: { eles: node } }, { duration: 300 });
      }
    }
  }, [selectedId]);

  // React to reachability-trace changes. When a trace is cleared, restore the
  // ordinary selection highlight underneath it.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    applyTrace(cy, trace);
    if (!trace) highlightSelection(cy, selectedRef.current);
  }, [trace]);

  // Keep the canvas correctly sized when the window/layout changes; Cytoscape
  // caches container dimensions, so without this a resize clips the map.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => cyRef.current?.resize());
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return <div ref={containerRef} className="graph-canvas" />;
}
