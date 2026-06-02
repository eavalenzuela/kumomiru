// cytoscape-expand-collapse ships no type declarations; it's a Cytoscape
// extension registered via cytoscape.use(). This file is a *script* (no
// top-level import/export) so the module declaration stands alone, mirroring
// cytoscape-elk.d.ts. The Core augmentation lives in a separate module file
// (cytoscape-augment.d.ts) because augmenting an existing module requires it.
declare module "cytoscape-expand-collapse" {
  import type { Ext } from "cytoscape";
  const ext: Ext;
  export default ext;
}
