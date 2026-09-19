import type { Framework } from "@kumomiru/graph";

export interface Control {
  id: string;
  title: string;
}

export interface Catalogue {
  framework: Framework;
  name: string;
  /** Catalogue revision, bumped when controls are added or retitled. */
  version: string;
  controls: Control[];
}
