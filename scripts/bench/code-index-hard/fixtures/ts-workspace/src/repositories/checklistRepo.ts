import { Table } from "../db";
import type { Checklist } from "../models/checklist";

const table = new Table<Checklist>("checklists");

export const checklistRepo = {
  getInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? row : undefined;
  },
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Checklist) => table.insert(row),
  updateInOrg(orgId: string, id: string, patch: Partial<Checklist>) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.update(id, patch) : undefined;
  },
  removeInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.remove(id) : false;
  },
};
