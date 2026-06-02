import cytoscape from "cytoscape";
import elk from "cytoscape-elk";
import expandCollapse from "cytoscape-expand-collapse";

/**
 * Register Cytoscape extensions exactly once. Calling `cytoscape.use` twice
 * throws in some versions, so we guard with a module-level flag.
 */
let registered = false;

export function ensureCytoscapeExtensions(): void {
  if (registered) return;
  cytoscape.use(elk);
  cytoscape.use(expandCollapse);
  registered = true;
}
