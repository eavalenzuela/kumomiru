import type { Database } from "@kumomiru/db";
import { CATALOGUES, isCheckRule, type RuleRegistry } from "@kumomiru/rules";

/**
 * Mirror the rule registry and framework catalogues into the database so the
 * API can list rules and controls (and reports can name them) without
 * importing the rules package at request time, and so results reference
 * rules that exist even before their first evaluation. Idempotent; run at
 * worker start.
 */
export function syncRuleMetadata(db: Database, registry: RuleRegistry): void {
  db.metadata.syncRules(
    registry.list().map((r) => ({
      id: r.id,
      version: r.version,
      title: r.title,
      severity: r.severity,
      kind: r.kind,
      resourceTypes: isCheckRule(r) ? r.resourceTypes : [],
      requires: isCheckRule(r) ? r.requires : [],
      controls: r.controls,
      remediation: r.remediation,
    })),
  );
  for (const c of CATALOGUES) db.metadata.syncControls(c.framework, c.version, c.controls);
}
