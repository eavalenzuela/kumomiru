import type { Core, NodeSingular } from "cytoscape";

/**
 * Hand-rolled semantic zoom (collapse/expand of compound containers). We don't
 * use cytoscape-expand-collapse because it throws inside its own collapse path
 * on this Cytoscape version.
 *
 * The subtlety: a Cytoscape compound parent is sized and positioned *from its
 * children*. If we merely hide the children, the parent loses its centroid
 * (position becomes null) and renders nowhere — which is why the previous
 * "collapse" left a blank gap instead of a chip. So on collapse we detach the
 * direct children (remembering their parent), which turns the container into a
 * normal leaf node that we can pin in place and draw as a chip; on expand we
 * re-attach them.
 */

const ORIG_PARENT = "_collapseParent";

/** Direct children remembered as belonging to a now-collapsed container. */
function detachedChildrenOf(cy: Core, id: string) {
  return cy.nodes().filter((n) => n.data(ORIG_PARENT) === id);
}

export function collapse(node: NodeSingular): void {
  if (!node.isParent() || node.hasClass("collapsed")) return;
  const cy = node.cy();
  const pos = { x: node.position("x"), y: node.position("y") };
  cy.batch(() => {
    node.descendants().addClass("collapsed-hidden");
    node.children().forEach((c) => {
      c.data(ORIG_PARENT, node.id());
    });
    node.children().move({ parent: null });
    node.addClass("collapsed");
  });
  // Pin the (now childless) container where it sat, so the chip stays put.
  node.position(pos);
}

export function expand(node: NodeSingular): void {
  if (!node.hasClass("collapsed")) return;
  const cy = node.cy();
  const id = node.id();
  cy.batch(() => {
    const children = detachedChildrenOf(cy, id);
    children.move({ parent: id });
    children.removeData(ORIG_PARENT);
    node.removeClass("collapsed");
    node.descendants().removeClass("collapsed-hidden");
    // Keep any descendant that is still independently collapsed hidden.
    cy.nodes(".collapsed").forEach((c) => {
      c.descendants().addClass("collapsed-hidden");
    });
  });
}

/** Toggle one container between collapsed and expanded (double-click). */
export function toggleCollapse(node: NodeSingular): void {
  if (node.hasClass("collapsed")) expand(node);
  else collapse(node);
}

/**
 * Collapse or expand "everything" (toolbar action). Because collapsing detaches
 * children — so a chip floats to the top level rather than nesting — we collapse
 * only the *innermost* containers (those with no container children). That keeps
 * the outer frame (account / region / VPC) readable while hiding the leaf
 * detail, which is the useful "zoom out" and avoids degenerate nested chips.
 */
export function setAllCollapsed(cy: Core, collapsed: boolean): void {
  if (collapsed) {
    cy.nodes()
      .filter((n) => n.isParent() && n.children(":parent").empty())
      .forEach((c) => collapse(c as NodeSingular));
  } else {
    cy.nodes(".collapsed").forEach((c) => expand(c as NodeSingular));
  }
}
