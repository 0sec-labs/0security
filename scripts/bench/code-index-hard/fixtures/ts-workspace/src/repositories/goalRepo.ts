import { Table } from "../db";
import type { Goal } from "../models/goal";

const table = new Table<Goal>("goals");

export const goalRepo = {
  getInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? row : undefined;
  },
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Goal) => table.insert(row),
  updateInOrg(orgId: string, id: string, patch: Partial<Goal>) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.update(id, patch) : undefined;
  },
  removeInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.remove(id) : false;
  },
};
