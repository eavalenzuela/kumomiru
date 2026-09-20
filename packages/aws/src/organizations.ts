/**
 * AWS Organizations discovery, run with the worker's HOST identity (the
 * management account or a delegated administrator), not a scan role. Lists
 * member accounts with their OU path so they can be registered for scanning.
 * Read-only; kumomiru never creates the StackSet itself.
 */
import {
  OrganizationsClient,
  DescribeOrganizationCommand,
  ListRootsCommand,
  ListOrganizationalUnitsForParentCommand,
  ListAccountsForParentCommand,
  type ListAccountsForParentCommandOutput,
  type ListOrganizationalUnitsForParentCommandOutput,
} from "@aws-sdk/client-organizations";

export const ORG_ACTIONS = [
  "organizations:DescribeOrganization",
  "organizations:ListRoots",
  "organizations:ListOrganizationalUnitsForParent",
  "organizations:ListAccountsForParent",
] as const;

export interface OrgAccount {
  id: string;
  name: string;
  email?: string;
  status: string;
  ouPath: string;
}

export interface OrgListing {
  orgId: string;
  managementAccountId?: string;
  accounts: OrgAccount[];
}

export interface OrganizationsApi {
  listAccounts(region: string): Promise<OrgListing>;
}

export const organizations: OrganizationsApi = {
  async listAccounts(region) {
    const client = new OrganizationsClient({ region });
    const org = (await client.send(new DescribeOrganizationCommand({}))).Organization;
    const roots = (await client.send(new ListRootsCommand({}))).Roots ?? [];
    const accounts: OrgAccount[] = [];

    const walk = async (parentId: string, path: string): Promise<void> => {
      let token: string | undefined;
      do {
        const res: ListAccountsForParentCommandOutput = await client.send(new ListAccountsForParentCommand({ ParentId: parentId, ...(token ? { NextToken: token } : {}) }));
        for (const a of res.Accounts ?? []) {
          if (!a.Id) continue;
          accounts.push({ id: a.Id, name: a.Name ?? a.Id, ...(a.Email ? { email: a.Email } : {}), status: a.Status ?? "ACTIVE", ouPath: path });
        }
        token = res.NextToken;
      } while (token);
      token = undefined;
      do {
        const res: ListOrganizationalUnitsForParentCommandOutput = await client.send(new ListOrganizationalUnitsForParentCommand({ ParentId: parentId, ...(token ? { NextToken: token } : {}) }));
        for (const ou of res.OrganizationalUnits ?? []) {
          if (ou.Id) await walk(ou.Id, `${path}/${ou.Name ?? ou.Id}`);
        }
        token = res.NextToken;
      } while (token);
    };
    for (const root of roots) if (root.Id) await walk(root.Id, root.Name ?? "Root");

    return {
      orgId: org?.Id ?? "unknown",
      ...(org?.MasterAccountId ? { managementAccountId: org.MasterAccountId } : {}),
      accounts,
    };
  },
};
