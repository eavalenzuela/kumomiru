import type { Finding } from "@kumomiru/graph";

/**
 * The sanitization layer (component "B" in the design): secrets DISCOVERED in
 * the environment must never enter the graph as values. Discovery collects
 * free-form text (EC2 user-data, Lambda/ECS env vars, tags) that may contain
 * hard-coded credentials. This module detects likely secret material, replaces
 * it with a marker, and emits a security Finding — turning a risk into a feature.
 *
 * This is distinct from secrets we deliberately never resolve at all (Secrets
 * Manager / SSM SecureString values): those we simply never fetch.
 */

export interface SecretMarker {
  secretPresent: true;
  kind: string;
}

interface Detector {
  kind: string;
  re: RegExp;
}

// Patterns are intentionally conservative: high-signal, low false-positive.
const DETECTORS: Detector[] = [
  { kind: "aws-access-key-id", re: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/ },
  {
    kind: "aws-secret-access-key",
    re: /\baws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+]{40}\b/i,
  },
  { kind: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { kind: "generic-secret-assignment", re: /\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*["'][^"'\s]{8,}["']/i },
];

export interface ScanResult {
  /** True if any secret was detected. */
  found: boolean;
  /** Distinct kinds detected, for the marker/finding. */
  kinds: string[];
}

/** Scan a single string for secret material. */
export function scanText(text: string): ScanResult {
  const kinds: string[] = [];
  for (const d of DETECTORS) {
    if (d.re.test(text) && !kinds.includes(d.kind)) kinds.push(d.kind);
  }
  return { found: kinds.length > 0, kinds };
}

/**
 * Scan a record of string-ish values (e.g. Lambda env vars). Returns the set of
 * keys whose values matched and the kinds found, so the caller can both mark
 * the attribute and raise a finding without ever storing the value.
 */
export function scanRecord(record: Record<string, unknown>): {
  found: boolean;
  keys: string[];
  kinds: string[];
} {
  const keys: string[] = [];
  const kinds = new Set<string>();
  for (const [k, v] of Object.entries(record)) {
    if (typeof v !== "string") continue;
    const res = scanText(`${k}=${v}`);
    if (res.found) {
      keys.push(k);
      res.kinds.forEach((kind) => kinds.add(kind));
    }
  }
  return { found: keys.length > 0, keys, kinds: [...kinds] };
}

/** A secret marker to drop into a node's attributes in place of any value. */
export function marker(kind: string): SecretMarker {
  return { secretPresent: true, kind };
}

/** Build a standard plaintext-secret finding for a node. */
export function plaintextSecretFinding(
  nodeId: string,
  where: string,
  kinds: string[],
): Finding {
  return {
    id: `f-secret-${hashId(nodeId + where)}`,
    severity: "high",
    kind: "plaintext-secret",
    nodeId,
    title: `Plaintext secret detected in ${where}`,
    detail: `Detected likely secret material (${kinds.join(
      ", ",
    )}) in ${where}. The value was redacted at ingestion; rotate the credential and move it to a secrets manager.`,
  };
}

/** Small stable id hash (djb2) so finding ids are deterministic, not random. */
function hashId(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (h * 33) ^ s.charCodeAt(i);
  return (h >>> 0).toString(36);
}
