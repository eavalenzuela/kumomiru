// cytoscape-elk ships no type declarations; it's a Cytoscape layout extension
// registered via cytoscape.use(). We only need it to be a usable module value.
declare module "cytoscape-elk" {
  import type { Ext } from "cytoscape";
  const ext: Ext;
  export default ext;
}
