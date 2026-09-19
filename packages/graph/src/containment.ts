/**
 * Node types that act as containers (Cytoscape compound parents), never as
 * leaf resources. Shared by adapters (which must not emit dataflow edges to a
 * container) and the viewer (which renders containers as compound nodes), so
 * the two can never disagree about what is a container.
 */
export const CONTAINER_TYPES: ReadonlySet<string> = new Set([
  "aws::account",
  "aws::region",
  "aws::ec2::vpc",
  "aws::ec2::subnet",
]);

export function isContainer(type: string): boolean {
  return CONTAINER_TYPES.has(type);
}
