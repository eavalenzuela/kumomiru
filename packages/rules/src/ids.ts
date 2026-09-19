/** Small stable id hash (djb2) — the same one the adapters use for their ids. */
export function hashId(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

export function findingId(ruleId: string, resourceId: string): string {
  return `f-${ruleId}-${hashId(resourceId)}`;
}
