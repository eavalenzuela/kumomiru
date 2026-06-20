import { useState } from "react";
import type { Core } from "cytoscape";
import { setAllCollapsed } from "../lib/collapse.js";

interface MapControlsProps {
  /** Returns the live Cytoscape instance, or null before it has mounted. */
  getCy: () => Core | null;
}

/**
 * Floating camera + semantic-zoom controls. Without these, a user who pans or
 * zooms off the map (ELK only fits once) has no way back, and the
 * collapse-to-chip feature is undiscoverable behind a double-click.
 */
export function MapControls({ getCy }: MapControlsProps) {
  const [collapsed, setCollapsed] = useState(false);

  const zoomBy = (factor: number) => {
    const cy = getCy();
    if (!cy) return;
    cy.zoom({
      level: cy.zoom() * factor,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    });
  };

  const fit = () => {
    const cy = getCy();
    if (cy) cy.animate({ fit: { eles: cy.elements(), padding: 40 } }, { duration: 250 });
  };

  const toggleCollapseAll = () => {
    const cy = getCy();
    if (!cy) return;
    const next = !collapsed;
    setAllCollapsed(cy, next);
    setCollapsed(next);
    // Positions don't change but the visible bounding box does, so refit.
    cy.animate({ fit: { eles: cy.elements(":visible"), padding: 40 } }, { duration: 250 });
  };

  return (
    <div className="map-controls">
      <button type="button" onClick={() => zoomBy(1.2)} title="Zoom in" aria-label="Zoom in">
        +
      </button>
      <button type="button" onClick={() => zoomBy(1 / 1.2)} title="Zoom out" aria-label="Zoom out">
        −
      </button>
      <button type="button" onClick={fit} title="Fit map to view" aria-label="Fit to view">
        ⤢
      </button>
      <button
        type="button"
        onClick={toggleCollapseAll}
        title={collapsed ? "Expand all containers" : "Collapse all containers"}
        aria-label={collapsed ? "Expand all containers" : "Collapse all containers"}
      >
        {collapsed ? "⊞" : "⊟"}
      </button>
    </div>
  );
}
