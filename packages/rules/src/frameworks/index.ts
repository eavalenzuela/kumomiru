import type { Framework } from "@kumomiru/graph";
import { FSBP } from "./fsbp.js";
import { NIST_CSF_2 } from "./nist-csf-2.js";
import type { Catalogue } from "./types.js";

export type { Catalogue, Control } from "./types.js";
export { FSBP, NIST_CSF_2 };

export const CATALOGUES: readonly Catalogue[] = [FSBP, NIST_CSF_2];

export function catalogue(framework: Framework): Catalogue {
  const c = CATALOGUES.find((x) => x.framework === framework);
  if (!c) throw new Error(`unknown framework: ${framework}`);
  return c;
}
