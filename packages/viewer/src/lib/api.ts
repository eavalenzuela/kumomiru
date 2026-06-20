import { parseGraph, type Graph } from "@kumomiru/graph";

/**
 * Fetch a graph from the kumomiru server. In dev, `/api` is proxied to the
 * server (see vite.config). The response is validated through the shared schema
 * before it ever reaches the renderer — the same schema the server produced it
 * with, so a drift would fail loudly here.
 */
export async function fetchGraph(path: string): Promise<Graph> {
  const res = await fetch(`/api${path}`);
  if (!res.ok) {
    throw new Error(`request failed: ${res.status} ${res.statusText}`);
  }
  return parseGraph(await res.json());
}

/** Convenience: the zero-setup sample graph served at GET /sample. */
export function fetchSample(): Promise<Graph> {
  return fetchGraph("/sample");
}

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
