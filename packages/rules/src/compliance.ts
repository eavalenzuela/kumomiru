import type { ControlStatus, Framework, RuleResult } from "@kumomiru/graph";

import { catalogue } from "./frameworks/index.js";
import type { RuleRegistry } from "./registry.js";

/**
 * Roll rule results up to framework controls. A control is `fail` if any
 * assessed resource under any of its rules failed, `pass` if everything
 * assessed passed (and at least one thing was assessed), else
 * `not-assessed` — which covers "no such resources" and "collector absent"
 * alike. Controls with no mapped rule are listed as not-assessed so the
 * report is honest about coverage.
 */
export function controlStatuses(
  framework: Framework,
  results: readonly RuleResult[],
  registry: RuleRegistry,
): ControlStatus[] {
  const rulesByControl = new Map<string, string[]>();
  for (const rule of registry.list()) {
    for (const c of rule.controls) {
      if (c.framework !== framework) continue;
      rulesByControl.set(c.id, [...(rulesByControl.get(c.id) ?? []), rule.id]);
    }
  }
  const byRule = new Map<string, RuleResult[]>();
  for (const r of results) byRule.set(r.ruleId, [...(byRule.get(r.ruleId) ?? []), r]);

  return catalogue(framework).controls.map((control) => {
    const ruleIds = rulesByControl.get(control.id) ?? [];
    let pass = 0, fail = 0, notAssessed = 0;
    const failing: string[] = [];
    for (const ruleId of ruleIds) {
      for (const r of byRule.get(ruleId) ?? []) {
        if (r.status === "pass") pass++;
        else if (r.status === "fail") {
          fail++;
          failing.push(r.resourceId);
        } else if (r.status === "not-assessed") notAssessed++;
      }
    }
    const status: ControlStatus["status"] = fail > 0 ? "fail" : pass > 0 ? "pass" : "not-assessed";
    return {
      framework,
      controlId: control.id,
      title: control.title,
      status,
      pass,
      fail,
      notAssessed,
      ruleIds,
      failingResourceIds: [...new Set(failing)],
    };
  });
}
