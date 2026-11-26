import { Table } from "../db";
import type { Tag } from "../models/tag";

const table = new Table<Tag>("tags");

export const tagRepo = {
  getInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? row : undefined;
  },
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Tag) => table.insert(row),
  updateInOrg(orgId: string, id: string, patch: Partial<Tag>) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.update(id, patch) : undefined;
  },
  removeInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.remove(id) : false;
  },
};
