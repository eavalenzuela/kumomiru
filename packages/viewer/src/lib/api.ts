import { parseGraph, type Graph } from "@kumomiru/graph";

/**
 * Fetch a graph from the kumomiru server. In dev, `/api` is proxied to the
 * server (see vite.config). The response is validated through the shared schema
 * before it ever reaches the renderer — the same schema the server produced it
 * with, so a drift would fail loudly here.
 */
/** Thrown when the server wants a login (OIDC is configured and there is no session). */
export class UnauthenticatedError extends Error {
  constructor() {
    super("sign-in required");
    this.name = "UnauthenticatedError";
  }
}

function checkAuth(res: Response): void {
  if (res.status === 401) throw new UnauthenticatedError();
}

export async function fetchGraph(path: string): Promise<Graph> {
  const res = await fetch(`/api${path}`);
  checkAuth(res);
  if (!res.ok) {
    throw new Error(`request failed: ${res.status} ${res.statusText}`);
  }
  return parseGraph(await res.json());
}

/** Convenience: the zero-setup sample graph served at GET /sample. */
export function fetchSample(): Promise<Graph> {
  return fetchGraph("/sample");
}

/**
 * URL of the least-privilege read-only IAM policy the server serves (the exact
 * action set discovery needs). Used as a download link so onboarding a scan role
 * is one click.
 */
export const leastPrivilegePolicyUrl = "/api/policy/least-privilege";

/** Credentials for live discovery — sent in the POST body only, never stored. */
export interface LiveCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region: string;
}

async function postGraph(path: string, body: unknown): Promise<Graph> {
  const res = await fetch(`/api${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  checkAuth(res);
  if (!res.ok) {
    // Surface the server's message (e.g. invalid state, discovery failed)
    // without assuming a shape.
    let detail = `${res.status} ${res.statusText}`;
    try {
      const j = (await res.json()) as { message?: string; error?: string };
      detail = j.message || j.error || detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return parseGraph(await res.json());
}

/** Build a Graph from a parsed Terraform state object (no credentials). */
export function postTerraform(state: unknown): Promise<Graph> {
  return postGraph("/map/terraform", state);
}

/**
 * Build a Graph from live read-only AWS discovery. Credentials go in the POST
 * body over TLS for exactly this one request; the caller must not persist them.
 */
export function postLive(creds: LiveCredentials): Promise<Graph> {
  return postGraph("/map/live", creds);
}

// --- Persisted accounts (Phase 1) --------------------------------------------

export interface AccountSummary {
  id: string;
  name: string;
  roleArn: string;
  regions: string[] | null;
  scheduleCron: string;
  status: "pending" | "active" | "inactive";
  latestSnapshot: {
    id: string;
    generatedAt: string;
    nodeCount: number;
    edgeCount: number;
    findingCount: number;
  } | null;
  activeScan: { id: string; status: string; trigger: string } | null;
  lastScan: {
    id: string;
    status: string;
    finishedAt: string | null;
    error: string | null;
  } | null;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`/api${path}`);
  checkAuth(res);
  if (!res.ok) throw new Error(`request failed: ${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

// --- Auth (Phase 5) -----------------------------------------------------------

export interface Me {
  authEnabled: boolean;
  user: { id: string; email: string; name: string | null; role: "viewer" | "admin" } | null;
}

/** Who am I, and is login even a thing on this server? Never throws on 401. */
export async function fetchMe(): Promise<Me> {
  const res = await fetch("/api/auth/me");
  if (!res.ok) return { authEnabled: true, user: null };
  return (await res.json()) as Me;
}

export const loginUrl = "/api/auth/login";

export async function logout(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST" });
}

/** Registered accounts with their latest snapshot and scan state. */
export function fetchAccounts(): Promise<AccountSummary[]> {
  return getJson<AccountSummary[]>("/accounts");
}

/** The most recent stored map for an account. 404 until a scan completes. */
export function fetchAccountLatest(accountId: string): Promise<Graph> {
  return fetchGraph(`/accounts/${encodeURIComponent(accountId)}/latest`);
}

/** Ask the worker to scan (or verify) an account now. */
export async function requestScan(
  accountId: string,
  trigger: "manual" | "verify" = "manual",
): Promise<void> {
  const res = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/scans`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ trigger }),
  });
  checkAuth(res);
  if (res.status === 403) throw new Error("admin role required to start a scan");
  if (!res.ok) throw new Error(`scan request failed: ${res.status}`);
}
