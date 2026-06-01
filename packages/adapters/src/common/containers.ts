import type { CloudNode } from "@kumomiru/graph";

/**
 * Builds container nodes (account, region) on demand and dedupes them, so the
 * containment chain account -> region -> resource always exists even when the
 * source (Terraform state, live AWS APIs) has no explicit account/region
 * resources. Shared by every adapter.
 */
export class Containers {
  readonly nodes = new Map<string, CloudNode>();

  account(account: string): string {
    const id = `aws::account::${account}`;
    if (!this.nodes.has(id)) {
      this.nodes.set(id, {
        id,
        type: "aws::account",
        name: account,
        account,
        tags: {},
        attributes: {},
      });
    }
    return id;
  }

  region(account: string, region: string): string {
    const id = `aws::region::${account}::${region}`;
    if (!this.nodes.has(id)) {
      this.nodes.set(id, {
        id,
        type: "aws::region",
        name: region,
        account,
        region,
        parent: this.account(account),
        tags: {},
        attributes: {},
      });
    }
    return id;
  }
}
