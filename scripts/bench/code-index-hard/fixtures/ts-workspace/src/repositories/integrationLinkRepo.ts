import { Table } from "../db";
import type { IntegrationLink } from "../models/integrationLink";

const table = new Table<IntegrationLink>("integration_links");

export const integrationLinkRepo = {
  getInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? row : undefined;
  },
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: IntegrationLink) => table.insert(row),
  updateInOrg(orgId: string, id: string, patch: Partial<IntegrationLink>) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.update(id, patch) : undefined;
  },
  removeInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.remove(id) : false;
  },
};
