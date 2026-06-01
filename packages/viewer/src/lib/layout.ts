import type { LayoutOptions } from "cytoscape";

/**
 * ELK layered layout options. Layered ("Sugiyama") gives the clean directional
 * "traffic flows this way" look and respects compound containment, which is
 * exactly what cloud topology wants — unlike a force-directed hairball.
 *
 * cytoscape-elk adds an `elk` field that isn't in the core LayoutOptions type,
 * so we build a plain options object and cast through `unknown`.
 */
export function elkLayout(): LayoutOptions {
  const options = {
    name: "elk",
    elk: {
      algorithm: "layered",
      "elk.direction": "RIGHT",
      "elk.layered.spacing.nodeNodeBetweenLayers": 60,
      "elk.spacing.nodeNode": 30,
      "elk.padding": "[top=30,left=20,bottom=20,right=20]",
      "elk.hierarchyHandling": "INCLUDE_CHILDREN",
    },
    fit: true,
    padding: 30,
  };
  return options as unknown as LayoutOptions;
}
