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
