import type { Core, NodeSingular } from "cytoscape";

/**
 * Apply a text search to the canvas: nodes whose name, type, or id contains the
 * query are highlighted (`search-hit`); everything else fades (`search-miss`).
 * Containers never fade so the structural frame stays readable. An empty query
 * clears all search classes. Returns the number of matched nodes.
 *
 * This layers on top of the lens dimming (separate classes), so search and the
 * active lens compose rather than fight.
 */
export function applySearch(cy: Core, query: string): number {
  const q = query.trim().toLowerCase();

  cy.batch(() => {
    if (!q) {
      cy.elements().removeClass("search-hit search-miss");
      return;
    }

    const isHit = (n: NodeSingular): boolean => {
      const d = n.data();
      return [d.label, d.kind, d.id].some(
        (v) => typeof v === "string" && v.toLowerCase().includes(q),
      );
    };

    cy.nodes().forEach((n) => {
      const hit = isHit(n);
      n.toggleClass("search-hit", hit);
      // Keep containers lit so the account/VPC/subnet frame never disappears.
      n.toggleClass("search-miss", !hit && !n.data("container"));
    });

    cy.edges().forEach((e) => {
      const between =
        e.source().hasClass("search-hit") && e.target().hasClass("search-hit");
      e.removeClass("search-hit");
      e.toggleClass("search-miss", !between);
    });
  });

  return q ? cy.nodes(".search-hit").length : 0;
}
