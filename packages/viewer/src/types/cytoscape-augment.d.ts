// Augment Cytoscape's Core with the `expandCollapse()` initializer the
// cytoscape-expand-collapse extension adds at runtime. The `export {}` makes
// this file a module so `declare module "cytoscape"` MERGES with cytoscape's
// real types rather than shadowing them.
export {};

declare module "cytoscape" {
  interface ExpandCollapseOptions {
    /** Layout to re-run after a collapse/expand, or null to keep positions. */
    layoutBy?: unknown;
    /** Animate the neighbourhood adjustment. */
    fisheye?: boolean;
    animate?: boolean;
    undoable?: boolean;
    /** Show the [-]/[+] cue on collapsible/expandable compound nodes. */
    cueEnabled?: boolean;
    expandCollapseCueSize?: number;
    expandCollapseCuePosition?: string;
  }

  interface ExpandCollapseApi {
    collapse(nodes: NodeCollection): void;
    expand(nodes: NodeCollection): void;
    collapseAll(): void;
    expandAll(): void;
    isCollapsible(node: NodeSingular): boolean;
    isExpandable(node: NodeSingular): boolean;
  }

  interface Core {
    expandCollapse(options?: ExpandCollapseOptions): ExpandCollapseApi;
  }
}
