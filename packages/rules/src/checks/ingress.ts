import type { CloudNode } from "@kumomiru/graph";

/** Mirror of adapters' IngressRule; the rules package does not depend on adapters. */
export interface IngressRule {
  fromPort?: number;
  toPort?: number;
  protocol?: string;
  cidrs: string[];
  sourceGroupIds: string[];
}

const PUBLIC = new Set(["0.0.0.0/0", "::/0"]);

export function ingressOf(node: CloudNode): IngressRule[] {
  const raw = node.attributes["ingress"];
  return Array.isArray(raw) ? (raw as IngressRule[]) : [];
}

export function isPublicRule(r: IngressRule): boolean {
  return r.cidrs.some((c) => PUBLIC.has(c));
}

function isAllProtocols(r: IngressRule): boolean {
  return r.protocol === undefined || r.protocol === "-1" || r.protocol === "all";
}

/** Whether the rule admits TCP or UDP traffic on `port`. */
export function coversPort(r: IngressRule, port: number): boolean {
  if (!(isAllProtocols(r) || r.protocol === "tcp" || r.protocol === "udp" || r.protocol === "6" || r.protocol === "17")) {
    return false;
  }
  if (isAllProtocols(r) && r.fromPort === undefined && r.toPort === undefined) return true;
  const from = r.fromPort ?? 0;
  const to = r.toPort ?? 65535;
  // Terraform / AWS express "all ports" as 0-0 with protocol -1, or 0-65535.
  if (from === 0 && (to === 0 || to === 65535) && isAllProtocols(r)) return true;
  return from <= port && port <= to;
}

/** Whether the rule admits any port outside `allowed`. */
export function coversPortOutside(r: IngressRule, allowed: ReadonlySet<number>): boolean {
  if (isAllProtocols(r) && (r.fromPort === undefined || (r.fromPort === 0 && (r.toPort === 0 || r.toPort === 65535)))) {
    return true;
  }
  if (!(isAllProtocols(r) || r.protocol === "tcp" || r.protocol === "udp" || r.protocol === "6" || r.protocol === "17")) {
    return false;
  }
  const from = r.fromPort ?? 0;
  const to = r.toPort ?? 65535;
  for (let p = from; p <= to; p++) {
    if (!allowed.has(p)) return true;
    if (p - from > 70000) break;
  }
  return false;
}

export function publicCidrs(r: IngressRule): string[] {
  return r.cidrs.filter((c) => PUBLIC.has(c));
}

export function portLabel(r: IngressRule): string {
  if (r.fromPort === undefined && r.toPort === undefined) return "all";
  if (r.fromPort === r.toPort) return String(r.fromPort);
  return `${r.fromPort ?? 0}-${r.toPort ?? 65535}`;
}
