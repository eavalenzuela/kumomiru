/**
 * Logging redaction. Even though the Terraform path handles no credentials, the
 * seam goes in now: anything that could carry a secret (live-API keys later,
 * session tokens, secret material spotted in resource attributes) must never
 * reach the logs. Fastify is configured with these redaction paths, and we keep
 * a key-name matcher for defense in depth.
 */

/** Fastify `logger.redact.paths` — request fields that may carry credentials. */
export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers["x-aws-access-key-id"]',
  'req.headers["x-aws-secret-access-key"]',
  'req.headers["x-aws-session-token"]',
  'req.body.credentials',
  'req.body.accessKeyId',
  'req.body.secretAccessKey',
  'req.body.sessionToken',
];

const SENSITIVE_KEY = /(secret|password|token|credential|accesskey|api[_-]?key)/i;

/**
 * Recursively replace values of sensitive-looking keys with "[REDACTED]".
 * Used before logging any object we did not construct ourselves.
 */
export function redactObject(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redactObject(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY.test(k) ? "[REDACTED]" : redactObject(v, depth + 1);
  }
  return out;
}
