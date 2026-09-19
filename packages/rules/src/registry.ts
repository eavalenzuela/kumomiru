import type { Rule } from "./types.js";
import { builtinRules } from "./checks/index.js";

export class RuleRegistry {
  readonly #rules = new Map<string, Rule>();

  register(rule: Rule): this {
    if (this.#rules.has(rule.id)) throw new Error(`duplicate rule id: ${rule.id}`);
    for (const old of rule.replaces ?? []) {
      if (this.#rules.has(old)) throw new Error(`rule ${rule.id} replaces ${old}, which is still registered`);
    }
    this.#rules.set(rule.id, rule);
    return this;
  }

  get(id: string): Rule | undefined {
    return this.#rules.get(id);
  }

  list(): Rule[] {
    return [...this.#rules.values()];
  }
}

/** Every built-in rule. */
export function defaultRegistry(): RuleRegistry {
  const r = new RuleRegistry();
  for (const rule of builtinRules) r.register(rule);
  return r;
}
